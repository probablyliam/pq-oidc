/**
 * Turns what a scan observed into findings, each labelled by how it is known
 * (ADR 0012): an observation carries its evidence, an inference carries its
 * reasoning and names the observations it rests on, and anything the scanner
 * could not establish is said outright.
 *
 * The quantum reasoning used here, in one place:
 *  - Key establishment (ECDH, finite-field DH, RSA key transport) is broken by
 *    Shor's algorithm, and recorded traffic can be decrypted afterwards. That
 *    is the urgent case: the recording can happen today.
 *  - Signatures (RSA, ECDSA, EdDSA) are broken by Shor's algorithm too, but a
 *    forgery needs the quantum computer at the time of the attack. Nothing
 *    recorded earlier becomes forgeable in retrospect.
 *  - Symmetric ciphers and hashes are only weakened (Grover). AES-256 and
 *    SHA-256/384 keep an ample margin.
 *  - ML-KEM, ML-DSA and SLH-DSA have no known quantum attack.
 *
 * Pure: no I/O and no Node APIs.
 */
import type { CertificateSummary, Finding, GroupSupport, LayerSummary, OidcSummary, ProbeResult, QuantumExposure, RelatedOrigin, Tone, TransportSummary, TrustResult } from './report.ts';
import { CIPHER_SUITES, cipherSuiteName, GROUPS, groupName, signatureSchemeName, SIGNATURE_SCHEMES, versionName } from './tls/registry.ts';

export interface Observations {
  hostname: string;
  lab: boolean;
  reachable: boolean;
  probes: ProbeResult[];
  groupSupport: GroupSupport[];
  certificates: CertificateSummary[];
  trust: TrustResult;
  transport: TransportSummary;
  oidc: OidcSummary;
  related: RelatedOrigin[];
}

export interface Assessment {
  layers: LayerSummary[];
  findings: Finding[];
}

const hex = (id: number) => `0x${id.toString(16).padStart(4, '0')}`;
const list = (items: string[]) => (items.length <= 1 ? (items[0] ?? '') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`);
/** The probe got far enough to show a ServerHello. */
const answered = (probe: ProbeResult | undefined): boolean => probe !== undefined && probe.version !== undefined && (probe.outcome === 'handshake' || probe.outcome === 'server-hello');
/**
 * The server turned the probe down before any ServerHello: a TLS alert, or a connection cut the same way on
 * two attempts. A timeout, or a connection cut once, was neither an answer nor a refusal: something in between
 * may have caused it.
 */
const refused = (probe: ProbeResult | undefined): boolean => probe !== undefined && (probe.outcome === 'alert' || (probe.outcome === 'closed' && probe.confirmed === true));
const ifAnswered = (probe: ProbeResult | undefined): ProbeResult | undefined => (answered(probe) ? probe : undefined);

/** How a completed handshake established its keys. */
function keyExchange(probe: ProbeResult): { label: string; kind: 'hybrid' | 'pq' | 'classical' | 'rsa-transport' | 'unknown'; parts: string[] } {
  if (probe.version === 0x0304 || probe.group !== undefined) {
    const info = probe.group === undefined ? undefined : GROUPS[probe.group];
    if (!info) return { label: probe.group === undefined ? 'an unreported group' : groupName(probe.group), kind: 'unknown', parts: [] };
    return { label: info.name, kind: info.kex, parts: info.components };
  }
  const suite = CIPHER_SUITES[probe.cipherSuite ?? -1];
  if (suite?.keyExchange === 'RSA') return { label: 'RSA key transport', kind: 'rsa-transport', parts: ['RSA encryption'] };
  if (suite?.keyExchange === 'DHE') return { label: `finite-field Diffie-Hellman${probe.dhPrimeBits ? ` (${probe.dhPrimeBits}-bit)` : ''}`, kind: 'classical', parts: ['Finite-field DH'] };
  return { label: 'an unidentified key exchange', kind: 'unknown', parts: [] };
}

const unanswered = (probe: ProbeResult) => (probe.alert ? `alert ${probe.alert}` : `${probe.detail ?? probe.outcome}${probe.confirmed ? ', on two attempts' : ''}`);

const helloEvidence = (probe: ProbeResult) => [
  { label: 'Scanner offered', value: `${list(probe.offered.groups.map(groupName))}; key shares for ${list(probe.offered.keyShares.map(groupName)) || 'none'}` },
  {
    label: 'ServerHello',
    value: `TLS ${versionName(probe.version!)}, ${cipherSuiteName(probe.cipherSuite!)}${probe.group === undefined ? '' : `, group ${hex(probe.group)} ${groupName(probe.group)}`}`,
  },
  ...(probe.finishedValid === undefined ? [] : [{ label: 'Finished MAC', value: probe.finishedValid ? 'verified: the scanner derived the same keys as the server' : 'did not verify' }]),
  ...(probe.retried ? [{ label: 'Note', value: 'the server first asked for a different key share (HelloRetryRequest)' }] : []),
];

export function assess(seen: Observations): Assessment {
  const findings: Finding[] = [];
  const layers: LayerSummary[] = [];
  const add = (finding: Finding) => findings.push(finding);
  const layer = (id: LayerSummary['id'], name: string, headline: string, exposure: QuantumExposure, tone: Tone) => layers.push({ id, name, headline, exposure, tone });

  if (!seen.reachable) {
    const detail = seen.probes[0]?.detail ?? 'No TCP connection could be made.';
    add({ id: 'net.unreachable', layer: 'key-establishment', kind: 'undetermined', tone: 'neutral', title: 'Nothing could be observed: the server did not accept a connection', detail });
    for (const [id, name] of LAYER_NAMES) layer(id, name, 'Could not determine', 'undetermined', 'neutral');
    return { layers, findings };
  }

  const main = seen.probes.find((p) => p.id === 'pq-capable-client');
  const classicalClient = seen.probes.find((p) => p.id === 'classical-client');
  const legacy = seen.probes.find((p) => p.id === 'tls12-client');
  /** The handshake the rest of the report describes: the capable client's if it worked, otherwise whichever did. */
  const best = ifAnswered(main) ?? ifAnswered(classicalClient) ?? ifAnswered(legacy);

  // ---------------------------------------------------------------- key establishment
  assessKeyEstablishment();
  function assessKeyEstablishment() {
    if (!best) {
      const outcomes = [main, classicalClient, legacy].filter((p) => p !== undefined).map((p) => `${p.id}: ${p.alert ?? p.detail ?? p.outcome}`);
      add({
        id: 'kex.undetermined',
        layer: 'key-establishment',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'No TLS handshake could be completed',
        detail: 'The server accepted a connection but none of the scanner’s handshakes got a usable answer, so the key exchange could not be observed.',
        evidence: outcomes.map((value, i) => ({ label: `Attempt ${i + 1}`, value })),
      });
      return layer('key-establishment', 'TLS key establishment', 'Could not determine', 'undetermined', 'neutral');
    }

    const mainAnswered = answered(main);
    const kex = keyExchange(best);
    const quantumSafe = kex.kind === 'hybrid' || kex.kind === 'pq';
    const tls12 = best.version !== 0x0304;

    add({
      id: 'kex.negotiated',
      layer: 'key-establishment',
      kind: 'observation',
      tone: quantumSafe ? 'good' : kex.kind === 'rsa-transport' ? 'bad' : 'caution',
      title:
        kex.kind === 'hybrid'
          ? `Key exchange: ${kex.label}, a hybrid of ${list(kex.parts)}`
          : kex.kind === 'pq'
            ? `Key exchange: ${kex.label}, post-quantum with no classical part`
            : kex.kind === 'rsa-transport'
              ? 'Key exchange: RSA key transport, with no forward secrecy'
              : `Key exchange: ${kex.label}, classical${tls12 ? ` (TLS ${versionName(best.version!)})` : ''}`,
      detail:
        kex.kind === 'hybrid'
          ? 'Negotiated by a client that offers post-quantum key exchange. The session keys depend on both parts, so they stay secret unless both are broken.'
          : kex.kind === 'pq'
            ? 'Negotiated by a client that offers post-quantum key exchange. The session keys depend on ML-KEM alone.'
            : kex.kind === 'rsa-transport'
              ? 'The client encrypts the session secret to the certificate’s RSA key. Anyone who later obtains that one private key can decrypt every session recorded before.'
              : !mainAnswered
                ? 'This is what a client without post-quantum support negotiated. The handshake that offered post-quantum key exchange was not completed.'
                : tls12
                  ? 'The server chose TLS 1.2 although TLS 1.3 was offered. TLS 1.2 has no post-quantum key exchange.'
                  : 'The scanner offered X25519MLKEM768 first and sent a key share for it. The server chose a classical group instead.',
      evidence: helloEvidence(best),
      learn: { view: 'login', landmark: 'key-establishment', mode: quantumSafe ? 'hybrid' : 'classical' },
    });

    // The classical handshake leaves out post-quantum groups and ML-DSA signatures together. With a post-quantum
    // certificate its refusal may be about the signatures, so the handshake that changes the key exchange only decides.
    const kexOnly = seen.probes.find((p) => p.id === 'classical-kex-client');
    const kexRefused = main?.leafKey?.quantumSafe ? refused(kexOnly) : refused(classicalClient);
    // A capable client was ignored but a plain one was answered: usually a large-ClientHello problem.
    const classicalAnswer = ifAnswered(classicalClient) ?? ifAnswered(kexOnly);
    if (main && !mainAnswered && classicalAnswer && ['timeout', 'closed', 'malformed'].includes(main.outcome)) {
      add({
        id: 'kex.large-hello',
        layer: 'key-establishment',
        kind: 'inference',
        tone: 'bad',
        title: 'The server, or something in front of it, drops handshakes that carry a post-quantum key share',
        detail:
          'A ClientHello that carries an ML-KEM-768 key share is larger than one network packet usually holds (the key share alone is about 1,200 bytes), so it is normally split across two. This server answered the small classical ClientHello but not the large one, which is the pattern of a load balancer or firewall that cannot handle a ClientHello split across packets. Clients that offer post-quantum key exchange may fail to connect.',
        basedOn: ['kex.negotiated'],
        evidence: [
          { label: 'Post-quantum-capable ClientHello', value: main.detail ?? main.outcome },
          { label: 'Classical ClientHello', value: `answered with TLS ${versionName(classicalAnswer.version!)}` },
        ],
      });
    }

    const fallback = classicalAnswer ? keyExchange(classicalAnswer) : undefined;
    if (quantumSafe && classicalClient) {
      const attempts = [
        { label: 'ClientHello with classical groups and classical signatures', value: unanswered(classicalClient) },
        ...(kexOnly ? [{ label: 'ClientHello with classical groups and ML-DSA signatures', value: answered(kexOnly) ? `answered with TLS ${versionName(kexOnly.version!)}` : unanswered(kexOnly) }] : []),
      ];
      add(
        fallback && classicalAnswer
          ? classicalAnswer === kexOnly
            ? {
                id: 'kex.classical-client',
                layer: 'key-establishment',
                kind: 'observation',
                tone: 'neutral',
                title: `A client that accepts the post-quantum certificate can still connect with classical key exchange (${fallback.label})`,
                detail: `The handshake that offered only classical groups and classical signature schemes ${refused(classicalClient) ? 'was refused' : 'got no answer'}, but one that kept ML-DSA signatures and offered only classical groups completed.${refused(classicalClient) ? ' So what stopped the first was the certificate, not the key exchange.' : ''} Sessions from such clients get classical key exchange.`,
                evidence: [...attempts, ...helloEvidence(classicalAnswer)],
              }
            : {
                id: 'kex.classical-client',
                layer: 'key-establishment',
                kind: 'observation',
                tone: 'neutral',
                title: `Clients without post-quantum support still connect, using ${fallback.label}`,
                detail: 'This keeps older browsers, libraries and devices working. Their sessions get classical key exchange.',
                evidence: helloEvidence(classicalAnswer),
              }
          : kexRefused
            ? {
                id: 'kex.classical-client',
                layer: 'key-establishment',
                kind: 'observation',
                tone: 'neutral',
                title: 'TLS 1.3 clients without post-quantum key exchange are refused',
                detail: 'A ClientHello offering only classical groups was rejected. Clients that cannot use post-quantum key exchange are locked out of TLS 1.3 here.',
                evidence: attempts,
              }
            : {
                id: 'kex.classical-client',
                layer: 'key-establishment',
                kind: 'undetermined',
                tone: 'neutral',
                title: 'What clients without post-quantum key exchange get could not be determined',
                detail: 'The handshake that would show it neither completed nor was clearly refused, so whether such clients can connect, and with what key exchange, is not known.',
                evidence: attempts,
              },
      );
    }

    if (legacy && best.version === 0x0304) {
      const legacyKex = answered(legacy) ? keyExchange(legacy) : undefined;
      add(
        legacyKex
          ? {
              id: 'kex.tls12',
              layer: 'key-establishment',
              kind: 'observation',
              tone: legacyKex.kind === 'rsa-transport' ? 'bad' : 'neutral',
              title: `TLS 1.2 is still accepted (${legacyKex.label})`,
              detail:
                legacyKex.kind === 'rsa-transport'
                  ? 'A TLS 1.2 client gets RSA key transport, which has no forward secrecy even against today’s attackers.'
                  : 'A client that only speaks TLS 1.2 gets classical key exchange; post-quantum groups exist only in TLS 1.3. TLS 1.3 has downgrade protection, so an attacker on the network cannot make a client that supports 1.3 settle for 1.2.',
              evidence: [{ label: 'ServerHello', value: `TLS ${versionName(legacy.version!)}, ${cipherSuiteName(legacy.cipherSuite!)}` }],
            }
          : refused(legacy)
            ? {
                id: 'kex.tls12',
                layer: 'key-establishment',
                kind: 'observation',
                tone: 'good',
                title: 'TLS 1.2 is not accepted',
                detail: 'A TLS 1.2 ClientHello was refused, so every connection uses TLS 1.3.',
                evidence: [{ label: 'TLS 1.2 ClientHello', value: unanswered(legacy) }],
              }
            : {
                id: 'kex.tls12',
                layer: 'key-establishment',
                kind: 'undetermined',
                tone: 'neutral',
                title: 'Whether TLS 1.2 is accepted could not be determined',
                detail: 'The TLS 1.2 handshake neither completed nor was clearly refused.',
                evidence: [{ label: 'TLS 1.2 ClientHello', value: unanswered(legacy) }],
              },
      );
    }

    const accepted = seen.groupSupport.filter((g) => g.supported === true);
    const unknown = seen.groupSupport.filter((g) => g.supported === undefined);
    if (seen.groupSupport.length > 0) {
      add({
        id: 'kex.groups',
        layer: 'key-establishment',
        kind: 'observation',
        tone: accepted.length > 0 ? 'good' : 'neutral',
        title: accepted.length > 0 ? `Post-quantum groups accepted: ${list(accepted.map((g) => g.name))}` : unknown.length > 0 ? 'No post-quantum key-exchange group was seen to be accepted' : 'No post-quantum key-exchange group is accepted',
        detail: `The scanner asked about each of ${seen.groupSupport.length} hybrid and ML-KEM groups separately.${unknown.length > 0 ? ` ${unknown.length} gave no usable answer.` : ''} A group it did not ask about cannot be detected.`,
        evidence: seen.groupSupport.map((g) => ({ label: g.name, value: `${g.supported === undefined ? 'unknown' : g.supported ? 'accepted' : 'not accepted'}: ${g.evidence}` })),
      });
    }

    // The conclusion for this layer.
    const basedOn = ['kex.negotiated', 'kex.classical-client', 'kex.tls12'].filter((id) => findings.some((f) => f.id === id));
    const fallbackSeen = fallback !== undefined || answered(legacy);
    const noFallback = !fallbackSeen && kexRefused && (legacy === undefined || refused(legacy));
    if (quantumSafe && noFallback) {
      add({
        id: 'kex.exposure',
        layer: 'key-establishment',
        kind: 'inference',
        tone: 'good',
        title: 'Traffic recorded today cannot be decrypted later by a quantum computer',
        detail: 'Every client that can connect negotiates ML-KEM (FIPS 203), for which no quantum attack is known. An attacker who stores this traffic gains nothing from a future quantum computer.',
        basedOn,
        learn: { view: 'login', landmark: 'harvest', mode: 'hybrid', attacker: 'quantum' },
      });
      layer('key-establishment', 'TLS key establishment', `${kex.kind === 'hybrid' ? 'Hybrid' : 'Post-quantum'}: ${kex.label}`, 'no-known-attack', 'good');
    } else if (quantumSafe && !fallbackSeen) {
      add({
        id: 'kex.exposure',
        layer: 'key-establishment',
        kind: 'inference',
        tone: 'caution',
        title: 'Sessions that negotiate ML-KEM are protected; what other clients get is not known',
        detail:
          'Sessions that negotiate ML-KEM cannot be decrypted later by a quantum computer. A handshake without post-quantum key exchange neither completed nor was clearly refused, so the scanner could not establish whether such clients are turned away or fall back to classical key exchange.',
        basedOn,
        learn: { view: 'login', landmark: 'harvest', mode: 'hybrid', attacker: 'quantum' },
      });
      layer('key-establishment', 'TLS key establishment', `${kex.kind === 'hybrid' ? 'Hybrid' : 'Post-quantum'}: ${kex.label}, other clients not determined`, 'depends-on-client', 'caution');
    } else if (quantumSafe) {
      add({
        id: 'kex.exposure',
        layer: 'key-establishment',
        kind: 'inference',
        tone: 'caution',
        title: 'Recorded traffic is protected only for clients that support post-quantum key exchange',
        detail:
          'Sessions that negotiate ML-KEM cannot be decrypted later by a quantum computer. Sessions from clients that fall back to classical key exchange can: an attacker who records them now can decrypt them once a large quantum computer exists ("harvest now, decrypt later"). Which of your clients fall back is not visible from outside.',
        basedOn,
        learn: { view: 'login', landmark: 'harvest', mode: 'hybrid', attacker: 'quantum' },
      });
      layer('key-establishment', 'TLS key establishment', `${kex.kind === 'hybrid' ? 'Hybrid' : 'Post-quantum'}: ${kex.label}, with classical fallback`, 'depends-on-client', 'caution');
    } else if (kex.kind === 'unknown') {
      add({
        id: 'kex.exposure',
        layer: 'key-establishment',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The key-exchange group is not one the scanner knows',
        detail: `The server selected ${kex.label}. Without knowing what it is, nothing can be said about its resistance to a quantum computer.`,
      });
      layer('key-establishment', 'TLS key establishment', kex.label, 'undetermined', 'neutral');
    } else {
      add({
        id: 'kex.exposure',
        layer: 'key-establishment',
        kind: 'inference',
        tone: 'bad',
        title: 'Traffic recorded today could be decrypted later by a quantum computer',
        detail:
          kex.kind === 'rsa-transport'
            ? 'The session secret is encrypted to an RSA key. Shor’s algorithm recovers an RSA private key from the public key, so an attacker who stores this traffic can decrypt all of it once a large enough quantum computer exists. A stolen private key does the same today.'
            : `The session keys come from ${kex.label} alone. Shor’s algorithm recovers the private value behind the public key share sent in the handshake, so an attacker who stores this traffic can decrypt it once a large enough quantum computer exists ("harvest now, decrypt later"). No such computer is known to exist. This is the most urgent quantum risk because the recording can happen now.`,
        basedOn,
        learn: { view: 'login', landmark: 'harvest', mode: 'classical', attacker: 'quantum' },
      });
      layer('key-establishment', 'TLS key establishment', `Classical: ${kex.label}`, 'harvest-now-decrypt-later', 'bad');
    }
  }

  // ---------------------------------------------------------------- server authentication
  assessServerAuthentication();
  function assessServerAuthentication() {
    const leaf = seen.certificates[0];
    if (!leaf) {
      add({
        id: 'auth.undetermined',
        layer: 'server-authentication',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The server’s certificate could not be read',
        detail: best ? 'A ServerHello was received, but the rest of the server’s handshake could not be read or decrypted.' : 'No handshake was completed.',
      });
      return layer('server-authentication', 'TLS server authentication', 'Could not determine', 'undetermined', 'neutral');
    }

    add({
      id: 'auth.certificate',
      layer: 'server-authentication',
      kind: 'observation',
      tone: leaf.key.quantumSafe ? 'good' : 'neutral',
      title: `Certificate key: ${leaf.key.algorithm}`,
      detail: `Issued to ${leaf.names[0] ?? leaf.subject} by "${leaf.issuer}", valid until ${leaf.notAfter.slice(0, 10)}. The server sent ${seen.certificates.length} certificate${seen.certificates.length === 1 ? '' : 's'}.`,
      evidence: seen.certificates.map((c) => ({
        label: c.position === 0 ? 'Leaf' : `Chain #${c.position}`,
        value: `${c.subject}; key ${c.key.algorithm}; signed by "${c.issuer}" with ${c.signature.algorithm}`,
      })),
      learn: { view: 'login', landmark: 'secure-channel', mode: leaf.key.quantumSafe ? 'pq' : 'classical' },
    });

    if (leaf.expired || leaf.notYetValid) {
      add({
        id: 'auth.validity',
        layer: 'server-authentication',
        kind: 'observation',
        tone: 'bad',
        title: leaf.expired ? `The certificate expired on ${leaf.notAfter.slice(0, 10)}` : `The certificate is not valid until ${leaf.notBefore.slice(0, 10)}`,
        detail: 'Browsers refuse this certificate regardless of its algorithms.',
        evidence: [{ label: 'Validity', value: `${leaf.notBefore} to ${leaf.notAfter}` }],
      });
    }

    const proof = best?.signatureScheme === undefined ? undefined : SIGNATURE_SCHEMES[best.signatureScheme];
    if (best?.signatureScheme !== undefined) {
      const message = best.version === 0x0304 ? 'CertificateVerify, a signature over the handshake transcript' : 'ServerKeyExchange, a signature over the key-exchange parameters';
      add({
        id: 'auth.proof',
        layer: 'server-authentication',
        kind: 'observation',
        tone: best.signatureValid === false ? 'bad' : 'neutral',
        title:
          best.signatureValid === false
            ? 'The server’s proof of key possession did not verify'
            : `The server proved it holds that key with ${signatureSchemeName(best.signatureScheme)}`,
        detail:
          best.signatureValid === true
            ? `The scanner checked ${message} against the leaf certificate’s public key. It is valid.`
            : best.signatureValid === false
              ? `${message} did not verify against the leaf certificate’s public key. That should never happen with a working server.`
              : `${message} uses a scheme or key type the scanner cannot check.`,
        evidence: [{ label: 'Signature scheme', value: `${hex(best.signatureScheme)} ${signatureSchemeName(best.signatureScheme)}` }],
      });
    } else if (best) {
      add({
        id: 'auth.proof',
        layer: 'server-authentication',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The scanner did not see the server prove it holds the certificate key',
        detail: 'With RSA key transport the proof is implicit: the server shows it can decrypt the client’s secret. The scanner stops before that step.',
      });
    }

    // Handshakes can be handed different certificates for two reasons that look alike from outside: the
    // server chose by what each offered, or the machines behind one address hold different certificates.
    // Only a post-quantum certificate for the handshake that offered ML-DSA, and a classical one for a
    // handshake that did not, points at the first.
    const sigOnly = seen.probes.find((p) => p.id === 'classical-sig-client');
    const leaves = [
      { probe: main, offering: 'Handshake offering ML-DSA signatures' },
      { probe: classicalClient, offering: 'Handshake offering classical signatures only' },
      { probe: sigOnly, offering: 'Handshake with post-quantum key exchange offering classical signatures only' },
      { probe: legacy, offering: 'TLS 1.2 handshake' },
    ].flatMap(({ probe, offering }) => (probe?.leafFingerprint ? [{ offering, fingerprint: probe.leafFingerprint, key: probe.leafKey }] : []));
    type LeafKey = NonNullable<ProbeResult['leafKey']>;
    const recognised = (key: LeafKey | undefined): key is LeafKey => key !== undefined && key.family !== 'unknown';
    const keyName = (key: LeafKey | undefined) => (recognised(key) ? key.algorithm : 'a key type the scanner does not recognise');
    const differ = new Set(leaves.map((l) => l.fingerprint)).size > 1;
    const offeredMlDsa = main?.leafKey;
    /** A classical certificate that a handshake without ML-DSA received. While clients accept one, it can be forged. */
    const classicalVariant = [classicalClient?.leafKey, sigOnly?.leafKey, legacy?.leafKey].find((key) => recognised(key) && !key.quantumSafe);
    const choseByOffer = differ && classicalVariant !== undefined && recognised(offeredMlDsa) && offeredMlDsa.quantumSafe;
    if (differ) {
      const kinds = [...new Set(leaves.map((l) => keyName(l.key)))];
      const allRecognised = leaves.every((l) => recognised(l.key));
      const keysSentence = !allRecognised ? '' : kinds.length === 1 ? `They carry the same kind of key (${kinds[0]}). ` : `Their keys are ${list(kinds)}. `;
      add({
        id: 'auth.variant',
        layer: 'server-authentication',
        kind: 'observation',
        tone: 'neutral',
        title: choseByOffer ? 'The scanner’s handshakes received certificates of different kinds' : 'The scanner’s handshakes received different certificates',
        detail: choseByOffer
          ? `The certificate sent to the handshake that offered ML-DSA signature schemes has a different kind of key (${offeredMlDsa.algorithm}) from the one sent to a handshake that offered only classical schemes (${classicalVariant.algorithm}). That is what a server holding both, and choosing by what the client offers, looks like. This report’s certificate details describe the first.`
          : `${keysSentence}A service run on several machines behind one address can hand out different certificates for the same name, so this alone does not show that the server chooses by what the client offers. This report’s certificate details describe the certificate from the first handshake that received one.`,
        evidence: leaves.map((l) => ({ label: l.offering, value: `${keyName(l.key)}, leaf SHA-256 ${l.fingerprint.slice(0, 16)}…` })),
      });
    }

    if (seen.trust.checked) {
      add({
        id: 'auth.trust',
        layer: 'server-authentication',
        kind: 'observation',
        tone: seen.trust.trusted ? 'good' : seen.lab ? 'neutral' : 'bad',
        title: seen.trust.trusted ? 'The certificate chain is publicly trusted and matches the host name' : `The certificate chain is not trusted: ${seen.trust.error ?? 'unknown reason'}`,
        detail: seen.trust.trusted
          ? `Validated by OpenSSL against ${seen.trust.store}.`
          : `Checked by OpenSSL against ${seen.trust.store}.${seen.lab ? ' Expected for a lab server: its certificate authority exists only on this machine.' : ''}`,
      });
    }

    // Every signature that vouches for this server: the leaf key's own, and each issuer's on the chain.
    // An algorithm the scanner does not recognise is neither classical nor post-quantum: nothing is claimed about it.
    const issued = seen.certificates.filter((c) => !c.selfSigned);
    const chainSignatures = (wanted: (c: CertificateSummary) => boolean) => [...new Set(issued.filter(wanted).map((c) => c.signature.algorithm))].map((a) => `a chain signature (${a})`);
    const classicalParts = [
      ...(leaf.key.quantumSafe || leaf.key.family === 'unknown' ? [] : [`the certificate key (${leaf.key.algorithm})`]),
      ...(proof && !proof.quantumSafe && leaf.key.quantumSafe ? [`the handshake signature (${proof.name})`] : []),
      ...chainSignatures((c) => !c.signature.quantumSafe && c.signature.family !== 'unknown'),
    ];
    const unknownParts = [...(leaf.key.family === 'unknown' ? [`the certificate key (${leaf.key.algorithm})`] : []), ...chainSignatures((c) => c.signature.family === 'unknown')];
    const pqParts = seen.certificates.filter((c) => c.key.quantumSafe || c.signature.quantumSafe).length;
    const basedOn = ['auth.certificate', 'auth.proof'].filter((id) => findings.some((f) => f.id === id && f.kind === 'observation'));
    // In this order: a classical part that was seen decides the matter, whatever else is unrecognised.
    if (classicalParts.length > 0) {
      add({
        id: 'auth.exposure',
        layer: 'server-authentication',
        kind: 'inference',
        tone: 'caution',
        title: 'A quantum computer could impersonate this server, but only at the time of an attack',
        detail: `The server’s identity rests on ${list(classicalParts)}. Shor’s algorithm recovers such private keys from the public keys, which would let an attacker present this identity. Unlike key exchange, this cannot be used on recorded traffic: the forgery has to be made, with a working quantum computer, during a live connection while the certificate is still valid.${pqParts > 0 ? ' Part of the chain is already post-quantum, but a chain is as strong as its weakest signature.' : ''}${unknownParts.length > 0 ? ` The chain also includes ${list(unknownParts)}, which the scanner does not recognise.` : ''} A public site cannot change this alone: it needs a certificate authority that browsers trust to issue post-quantum certificates, and the exposure lasts while browsers also accept classical ones.`,
        basedOn,
        learn: { view: 'login', landmark: 'forgery', mode: 'classical', attacker: 'quantum' },
      });
      layer('server-authentication', 'TLS server authentication', `Classical: ${leaf.key.algorithm} certificate`, 'forgery-once-quantum', 'caution');
    } else if (classicalVariant) {
      add({
        id: 'auth.exposure',
        layer: 'server-authentication',
        kind: 'inference',
        tone: 'caution',
        title: 'A quantum computer could still impersonate this server to clients that accept its classical certificate',
        detail: `The chain this report describes ${unknownParts.length === 0 ? 'is post-quantum throughout' : 'has no classical part the scanner recognises'}, but a handshake that did not offer ML-DSA signatures received a certificate with a classical key (${classicalVariant.algorithm}). While clients accept a classical certificate for this name, an attacker who can forge one can present this identity to them. That takes a working quantum computer during a live connection; it cannot be used on recorded traffic.`,
        basedOn: [...basedOn, ...(differ ? ['auth.variant'] : [])],
        learn: { view: 'login', landmark: 'forgery', mode: 'classical', attacker: 'quantum' },
      });
      layer(
        'server-authentication',
        'TLS server authentication',
        leaf.key.quantumSafe ? `Migrating: ${leaf.key.algorithm} and ${classicalVariant.algorithm}` : `Classical: ${classicalVariant.algorithm} certificate, for some clients`,
        'forgery-once-quantum',
        'caution',
      );
    } else if (unknownParts.length > 0) {
      add({
        id: 'auth.exposure',
        layer: 'server-authentication',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The server’s identity uses an algorithm the scanner does not recognise',
        detail: `The server’s identity rests in part on ${list(unknownParts)}. Without knowing what ${unknownParts.length === 1 ? 'that is' : 'these are'}, nothing can be said about how it stands against a quantum computer.`,
      });
      layer('server-authentication', 'TLS server authentication', leaf.key.family === 'unknown' ? 'Unrecognised certificate key' : `${leaf.key.algorithm} certificate, unrecognised chain signature`, 'undetermined', 'neutral');
    } else {
      const families = [...new Set(seen.certificates.flatMap((c) => [c.key, c.signature]).filter((part) => part.quantumSafe).map((part) => part.family))];
      add({
        id: 'auth.exposure',
        layer: 'server-authentication',
        kind: 'inference',
        tone: 'good',
        title: 'No known quantum attack on the certificate chain this server sent',
        detail: `The certificate key and every signature on the chain the server sent are post-quantum (${list(families)}), and no quantum algorithm is known that forges them. That protects clients that accept only such certificates for this name: a client that also accepts a classical certificate could be shown a forged one, and what clients accept is not visible to a scan.`,
        basedOn,
        learn: { view: 'login', landmark: 'forgery', mode: 'pq', attacker: 'quantum' },
      });
      layer('server-authentication', 'TLS server authentication', `Post-quantum: ${leaf.key.algorithm}`, 'no-known-attack', 'good');
    }
  }

  // ---------------------------------------------------------------- record protection
  assessRecordProtection();
  function assessRecordProtection() {
    const suite = best?.cipherSuite === undefined ? undefined : CIPHER_SUITES[best.cipherSuite];
    if (!best || !suite) {
      add({
        id: 'cipher.undetermined',
        layer: 'record-protection',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The cipher could not be determined',
        detail: best ? `The server chose cipher suite ${hex(best.cipherSuite ?? 0)}, which is not in the scanner’s registry.` : 'No handshake was completed.',
      });
      return layer('record-protection', 'Encryption of the data itself', 'Could not determine', 'undetermined', 'neutral');
    }
    add({
      id: 'cipher.negotiated',
      layer: 'record-protection',
      kind: 'observation',
      tone: suite.aead ? 'neutral' : 'caution',
      title: `Data is encrypted with ${suite.cipher}${suite.aead ? '' : ', an older non-AEAD construction'}`,
      detail: `Cipher suite ${suite.name}. The key for it comes out of the key exchange above; the cipher itself uses no public-key cryptography.`,
      evidence: [{ label: 'Cipher suite', value: `${hex(suite.id)} ${suite.name}` }],
      learn: { view: 'login', landmark: 'authentication', mode: 'classical' },
    });
    const strong = suite.keyBits >= 256;
    add({
      id: 'cipher.exposure',
      layer: 'record-protection',
      kind: 'inference',
      tone: strong ? 'good' : 'neutral',
      title: strong ? 'The cipher is not at risk from a quantum computer' : `A ${suite.keyBits}-bit key keeps a reduced margin against a quantum computer`,
      detail: strong
        ? 'Quantum computers do not break symmetric ciphers. Grover’s algorithm at best halves the effective key length, which leaves a 256-bit key with about 128 bits of security.'
        : `Quantum computers do not break symmetric ciphers. Grover’s algorithm could in theory search a ${suite.keyBits}-bit key in about 2^${suite.keyBits / 2} steps, but the steps cannot be spread across machines the way a classical search can, and NIST treats AES-128 as its baseline security category. Guidance that plans decades ahead, such as CNSA 2.0, asks for AES-256.`,
      basedOn: ['cipher.negotiated'],
    });
    layer('record-protection', 'Encryption of the data itself', suite.cipher, 'reduced-margin', strong ? 'good' : 'neutral');
  }

  // ---------------------------------------------------------------- transport policy
  assessTransport();
  function assessTransport() {
    const { transport } = seen;
    const first = transport.hops[0];
    if (!first || first.status === undefined) {
      add({
        id: 'http.undetermined',
        layer: 'transport-policy',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The page could not be fetched over HTTPS',
        detail: first?.error ?? 'No HTTP request was made.',
      });
      return layer('transport-policy', 'Is HTTPS enforced?', 'Could not determine', 'not-applicable', 'neutral');
    }

    if (transport.hops.length > 1 || transport.blockedRedirect) {
      add({
        id: 'http.redirects',
        layer: 'transport-policy',
        kind: 'observation',
        tone: 'neutral',
        title: transport.blockedRedirect ? 'The page redirects somewhere the scanner will not go' : `The page redirects ${transport.hops.length - 1} time${transport.hops.length === 2 ? '' : 's'}`,
        detail: transport.blockedRedirect ? `Not followed: ${transport.blockedRedirect.reason}` : 'Each hop was checked against the scanner’s target rules before it was followed.',
        evidence: [
          ...transport.hops.map((hop, i) => ({ label: `Hop ${i + 1}`, value: `${hop.url} → ${hop.status ?? hop.error}${hop.location ? ` → ${hop.location}` : ''}` })),
          ...(transport.blockedRedirect ? [{ label: 'Refused', value: `${transport.blockedRedirect.location} (${transport.blockedRedirect.code})` }] : []),
        ],
      });
    }

    const { hsts, plainHttp } = transport;
    const days = hsts?.maxAge === undefined ? undefined : Math.floor(hsts.maxAge / 86_400);
    const hstsUseful = hsts !== undefined && (hsts.maxAge ?? 0) > 0;
    add({
      id: 'http.hsts',
      layer: 'transport-policy',
      kind: 'observation',
      tone: hstsUseful ? 'good' : 'caution',
      title: hstsUseful ? `HSTS tells browsers to use HTTPS only, for ${days} day${days === 1 ? '' : 's'}` : hsts ? 'HSTS is present but switched off (max-age=0)' : 'No HSTS header',
      detail: hstsUseful
        ? 'A browser that has seen this header refuses to talk to the site over plain HTTP until it expires.'
        : 'Without Strict-Transport-Security a browser will use plain HTTP if a link or an attacker sends it there.',
      evidence: hsts ? [{ label: 'Strict-Transport-Security', value: hsts.raw }] : [{ label: 'Response headers', value: 'no Strict-Transport-Security header' }],
    });

    if (plainHttp) {
      const served = plainHttp.status !== undefined && !plainHttp.upgradesToHttps;
      add({
        id: 'http.plain',
        layer: 'transport-policy',
        kind: 'observation',
        tone: plainHttp.upgradesToHttps ? 'good' : served ? 'caution' : 'neutral',
        title: plainHttp.upgradesToHttps ? 'Plain HTTP redirects to HTTPS' : served ? `Plain HTTP answers with ${plainHttp.status} instead of redirecting to HTTPS` : 'Plain HTTP is not answered',
        detail: plainHttp.upgradesToHttps
          ? 'A request to port 80 is sent to the HTTPS site.'
          : served
            ? 'A request to port 80 is answered without being sent to HTTPS.'
            : 'Port 80 gave no HTTP answer, so there is no plain-HTTP site to fall back to.',
        evidence: [{ label: 'GET http://…:80/', value: plainHttp.error ?? `${plainHttp.status}${plainHttp.location ? ` → ${plainHttp.location}` : ''}` }],
      });
    }

    const insecure = transport.cookies.filter((c) => !c.secure);
    if (transport.cookies.length > 0) {
      add({
        id: 'http.cookies',
        layer: 'transport-policy',
        kind: 'observation',
        tone: insecure.length > 0 ? 'caution' : 'good',
        title:
          insecure.length > 0
            ? `Cookie ${list(insecure.map((c) => c.name))} can be sent over plain HTTP`
            : `Cookies set by this page are restricted to HTTPS`,
        detail:
          insecure.length > 0
            ? 'A cookie without the Secure attribute is sent on plain-HTTP requests too, where anyone on the network path can read it. Whether that matters depends on what the cookie is for, which a scan cannot tell: for a session cookie it means the session can be stolen.'
            : 'Every cookie has the Secure attribute.',
        evidence: transport.cookies.map((c) => ({
          label: c.name,
          value: [c.secure ? 'Secure' : 'not Secure', c.httpOnly ? 'HttpOnly' : 'readable by scripts', c.sameSite ? `SameSite=${c.sameSite}` : 'no SameSite'].join(', '),
        })),
      });
    }

    if (!hstsUseful) {
      add({
        id: 'http.exposure',
        layer: 'transport-policy',
        kind: 'inference',
        tone: 'caution',
        title: 'An attacker on the network can keep a first-time visitor off HTTPS',
        detail:
          'With no HSTS, a browser that is sent to the plain-HTTP address makes that request in the clear. An attacker on the path can answer it and never let the TLS handshake happen. The strength of the key exchange is irrelevant to a connection that was never encrypted. This is a classical attack, not a quantum one.',
        basedOn: ['http.hsts', ...(plainHttp ? ['http.plain'] : [])],
      });
    }
    layer('transport-policy', 'Is HTTPS enforced?', hstsUseful ? 'HSTS set' : 'No HSTS', 'not-applicable', hstsUseful && insecure.length === 0 ? 'good' : 'caution');
  }

  // ---------------------------------------------------------------- token signing
  assessTokenSigning();
  function assessTokenSigning() {
    const { oidc } = seen;
    if (!oidc.found) {
      add({
        id: 'token.undetermined',
        layer: 'token-signing',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'Unable to determine the application-level token signing algorithm',
        detail:
          'No OpenID Connect or OAuth metadata is published at this address. A service can issue signed tokens without saying how; from outside that is only visible in a token itself. If this system gives you a token, paste it into the token analyzer.',
        evidence: oidc.tried.map((t) => ({ label: t.url, value: t.result })),
        learn: { view: 'token' },
      });
      return layer('token-signing', 'Application token signing', 'Could not determine', 'undetermined', 'neutral');
    }

    const algs = oidc.idTokenAlgs ?? [];
    add({
      id: 'token.metadata',
      layer: 'token-signing',
      kind: 'observation',
      tone: algs.some((a) => a.toLowerCase() === 'none') ? 'bad' : 'neutral',
      title: algs.length > 0 ? `Sign-in tokens are signed with ${list(algs)}` : 'OpenID Connect metadata is published, without a list of signing algorithms',
      detail: `Read from the service’s own metadata. This is the application’s signature on a token, separate from anything TLS does.${algs.some((a) => a.toLowerCase() === 'none') ? ' The list includes "none": unsigned tokens.' : ''}`,
      evidence: [
        { label: 'Metadata', value: oidc.discoveryUrl ?? '' },
        { label: 'issuer', value: `${oidc.issuer}${oidc.issuerMatches ? '' : ' (does not match the URL it was served from)'}` },
        { label: 'id_token_signing_alg_values_supported', value: algs.join(', ') || '(absent)' },
      ],
      learn: { view: 'login', landmark: 'success', mode: 'classical' },
    });

    /** Without keys to read, the algorithms the service lists are all there is to go on. True when every one is a classical signature. */
    const classicalByMetadata = (): boolean => {
      const signed = algs.filter((a) => a.toLowerCase() !== 'none');
      if (signed.length === 0 || !signed.every((a) => CLASSICAL_JWS.test(a))) return false;
      add({
        id: 'token.exposure',
        layer: 'token-signing',
        kind: 'inference',
        tone: 'caution',
        title: 'A quantum computer could forge this service’s tokens once it exists',
        detail: `The service’s metadata says it signs tokens with ${list(signed)}, which Shor’s algorithm breaks. No signing keys could be read, so this rests on the metadata alone.`,
        basedOn: ['token.metadata'],
        learn: { view: 'login', landmark: 'forgery', mode: 'classical', attacker: 'quantum' },
      });
      layer('token-signing', 'Application token signing', `Classical: ${list(signed)}`, 'forgery-once-quantum', 'caution');
      return true;
    };

    if (!oidc.keys) {
      add({
        id: 'token.keys',
        layer: 'token-signing',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The signing keys could not be read',
        detail: oidc.jwksError ?? 'The key set was not available.',
        evidence: oidc.jwksUri ? [{ label: 'jwks_uri', value: oidc.jwksUri }] : undefined,
      });
      if (classicalByMetadata()) return;
      return layer('token-signing', 'Application token signing', algs.join(', ') || 'Metadata without keys', 'undetermined', 'neutral');
    }

    const kindsOf = (keys: typeof oidc.keys) => [...new Set(keys.map((k) => k.strength))];
    const kinds = kindsOf(oidc.keys);
    const safe = oidc.keys.filter((k) => k.quantumSafe);
    // RSA, elliptic-curve and Edwards-curve keys are the ones Shor’s algorithm is known to break. Anything else that is not post-quantum is unrecognised.
    const classical = oidc.keys.filter((k) => !k.quantumSafe && ['RSA', 'EC', 'OKP'].includes(k.kty));
    const unrecognised = oidc.keys.filter((k) => !k.quantumSafe && !['RSA', 'EC', 'OKP'].includes(k.kty));
    add({
      id: 'token.keys',
      layer: 'token-signing',
      kind: 'observation',
      tone: safe.length === oidc.keys.length && safe.length > 0 ? 'good' : 'neutral',
      title: `Signing keys published: ${list(kinds) || 'none'}`,
      detail: `${oidc.keys.length} key${oidc.keys.length === 1 ? '' : 's'} in the key set that apps use to check tokens.`,
      evidence: [{ label: 'jwks_uri', value: oidc.jwksUri ?? '' }, ...oidc.keys.map((k) => ({ label: k.kid ?? '(no kid)', value: `${k.strength}${k.alg ? `, alg ${k.alg}` : ''}` }))],
    });

    const basedOn = ['token.metadata', 'token.keys'];
    if (oidc.keys.length === 0) {
      if (!classicalByMetadata()) layer('token-signing', 'Application token signing', 'No signing keys published', 'undetermined', 'neutral');
    } else if (classical.length === 0 && unrecognised.length > 0) {
      const which = kindsOf(unrecognised);
      add({
        id: 'token.exposure',
        layer: 'token-signing',
        kind: 'undetermined',
        tone: 'neutral',
        title: 'The signing keys include a type the scanner does not recognise',
        detail: `The key set has ${list(which)}. Without knowing what ${which.length === 1 ? 'that is' : 'these are'}, nothing can be said about how tokens signed with ${which.length === 1 ? 'it' : 'them'} stand against a quantum computer.`,
      });
      layer('token-signing', 'Application token signing', 'Signing keys not recognised', 'undetermined', 'neutral');
    } else if (safe.length === oidc.keys.length) {
      add({
        id: 'token.exposure',
        layer: 'token-signing',
        kind: 'inference',
        tone: 'good',
        title: 'No known quantum attack forges this service’s tokens',
        detail: `Every published signing key is post-quantum (${list(kinds)}). Apps check token signatures against these keys, so a signature made with any other public-key algorithm is refused by an app that verifies correctly.`,
        basedOn,
        learn: { view: 'login', landmark: 'forgery', mode: 'pq', attacker: 'quantum' },
      });
      layer('token-signing', 'Application token signing', `Post-quantum: ${list(kinds)}`, 'no-known-attack', 'good');
    } else {
      const mixed = safe.length > 0;
      add({
        id: 'token.exposure',
        layer: 'token-signing',
        kind: 'inference',
        tone: 'caution',
        title: mixed ? 'Tokens signed with the classical key could be forged once a quantum computer exists' : 'A quantum computer could forge this service’s tokens once it exists',
        detail: `${mixed ? 'The service publishes a post-quantum key next to a classical one, which is what a migration in progress looks like. Apps still receiving classically signed tokens remain exposed. ' : ''}Shor’s algorithm recovers an RSA or elliptic-curve private key from the published public key; with it an attacker can sign a token for any user. A forged signature cannot be applied to the past, so there is nothing to record and attack later: the risk begins when such a computer exists.${unrecognised.length > 0 ? ` The key set also has ${list(kindsOf(unrecognised))}, which the scanner does not recognise.` : ''}`,
        basedOn,
        learn: { view: 'login', landmark: 'forgery', mode: 'classical', attacker: 'quantum' },
      });
      layer('token-signing', 'Application token signing', mixed ? `Migrating: ${list(kindsOf([...safe, ...classical]))}` : `Classical: ${list(kindsOf(classical))}`, 'forgery-once-quantum', 'caution');
    }
  }

  // ---------------------------------------------------------------- dependencies
  if (seen.related.length > 0) {
    add({
      id: 'deps.related',
      layer: 'dependencies',
      kind: 'observation',
      tone: 'neutral',
      title: `This sign-in also depends on ${seen.related.length} other origin${seen.related.length === 1 ? '' : 's'}`,
      detail: 'They were not scanned. Each has its own TLS configuration and keys, and the sign-in is only as strong as the weakest of them.',
      evidence: seen.related.map((r) => ({ label: r.origin, value: r.role })),
    });
  }
  add({
    id: 'deps.internal',
    layer: 'dependencies',
    kind: 'undetermined',
    tone: 'neutral',
    title: 'Internal dependencies cannot be observed from outside',
    detail:
      'Connections between your own services, databases, key storage, vendor APIs and the devices your users connect from all use cryptography too. None of it is visible to an external scan. Finding it is the first step of a migration.',
  });
  layer(
    'dependencies',
    'Dependencies',
    seen.related.length > 0 ? `${seen.related.length} related origin${seen.related.length === 1 ? '' : 's'} found; internal ones not observable` : 'Internal dependencies not observable',
    'undetermined',
    'neutral',
  );

  return { layers, findings };
}

/** JOSE signature algorithms built on RSA or elliptic curves, which Shor’s algorithm breaks: the names token-kit’s jose.ts classifies that way. */
const CLASSICAL_JWS = /^(?:RS|PS|ES)(?:256|384|512)$|^ES256K$|^EdDSA$|^Ed(?:25519|448)$/;

const LAYER_NAMES: [LayerSummary['id'], string][] = [
  ['key-establishment', 'TLS key establishment'],
  ['server-authentication', 'TLS server authentication'],
  ['record-protection', 'Encryption of the data itself'],
  ['transport-policy', 'Is HTTPS enforced?'],
  ['token-signing', 'Application token signing'],
  ['dependencies', 'Dependencies'],
];
