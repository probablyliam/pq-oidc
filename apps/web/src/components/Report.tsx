import { NOT_OBSERVABLE } from '@pq-oidc/scan-core/report';
import type { Finding as ScanFinding, LayerId, LayerSummary, QuantumExposure, ScanReport } from '@pq-oidc/scan-core/report';
import { cipherSuiteName, GROUPS, groupName, signatureSchemeName, versionName } from '@pq-oidc/scan-core/registry';
import { href } from '../router.ts';
import { Finding, KIND_MEANING, KindMark } from './Finding.tsx';
import type { Kind } from './Finding.tsx';

/** What each exposure class means, in the words used on the layer stack. */
export const EXPOSURE: Record<QuantumExposure, string> = {
  'harvest-now-decrypt-later': 'Traffic recorded today can be decrypted later',
  'depends-on-client': 'Protected only for clients that support it',
  'forgery-once-quantum': 'Forgeable once a quantum computer exists',
  'reduced-margin': 'Weakened at most, not broken',
  'no-known-attack': 'No known quantum attack',
  'not-applicable': 'Not a quantum question',
  undetermined: 'Could not determine',
};

const when = (iso: string) => new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

/** The parts of a key-exchange group, drawn in the same grammar as the learning stage: dotted means post-quantum. */
function GroupParts({ group }: { group: number }) {
  const info = GROUPS[group];
  if (!info) return null;
  return (
    <span className="parts" aria-label={`${info.name}: ${info.components.join(' plus ')}`}>
      {info.components.map((part) => (
        <span key={part} className={/ML-KEM|Kyber/.test(part) ? 'part pq' : 'part classical'}>
          {part}
        </span>
      ))}
    </span>
  );
}

function LayerRow({ layer, count }: { layer: LayerSummary; count: number }) {
  return (
    <li className={`layer-row tone-${layer.tone} ${layer.exposure === 'undetermined' ? 'unknown' : ''}`}>
      <a
        href={`#layer-${layer.id}`}
        onClick={(event) => {
          event.preventDefault();
          document.getElementById(`layer-${layer.id}`)?.scrollIntoView();
        }}
      >
        <span className="layer-name">{layer.name}</span>
        <span className="layer-headline">{layer.headline}</span>
        <span className="layer-exposure">{EXPOSURE[layer.exposure]}</span>
        <span className="sr-only">, {count} findings</span>
      </a>
    </li>
  );
}

function Triad({ report }: { report: ScanReport }) {
  const observed = report.layers.filter((l) => l.exposure !== 'undetermined' || l.id === 'dependencies');
  const unknown = report.findings.filter((f) => f.kind === 'undetermined');
  const attention = report.findings.filter((f) => f.tone === 'bad' || (f.tone === 'caution' && f.kind === 'inference'));
  const jump = (id: string) => (event: React.MouseEvent) => {
    event.preventDefault();
    document.getElementById(id)?.scrollIntoView({ block: 'center' });
  };
  return (
    <div className="triad">
      <section>
        <h3>What was observed</h3>
        <ul>
          {observed
            .filter((l) => l.id !== 'dependencies')
            .map((l) => (
              <li key={l.id}>
                <a href={`#layer-${l.id}`} onClick={jump(`layer-${l.id}`)}>
                  {l.headline}
                </a>
              </li>
            ))}
        </ul>
      </section>
      <section>
        <h3>What could not be determined</h3>
        <ul>
          {unknown.map((f) => (
            <li key={f.id}>
              <a href={`#finding-${f.id}`} onClick={jump(`finding-${f.id}`)}>
                {f.title}
              </a>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3>What may need a closer look</h3>
        {attention.length === 0 ? (
          <p className="fine">Nothing in this scan stands out.</p>
        ) : (
          <ul>
            {attention.map((f) => (
              <li key={f.id} className={`tone-${f.tone}`}>
                <a href={`#finding-${f.id}`} onClick={jump(`finding-${f.id}`)}>
                  {f.title}
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

const KIND_ORDER: ScanFinding['kind'][] = ['observation', 'inference', 'undetermined'];

function LayerSection({ layer, report }: { layer: LayerSummary; report: ScanReport }) {
  const findings = report.findings.filter((f) => f.layer === layer.id);
  const main = report.tls.probes.find((p) => p.id === 'pq-capable-client');
  return (
    <section className={`layer tone-${layer.tone}`} id={`layer-${layer.id}`}>
      <header>
        <h3>{layer.name}</h3>
        <p className="layer-headline">
          {layer.headline}
          {layer.id === 'key-establishment' && main?.group !== undefined && <GroupParts group={main.group} />}
        </p>
      </header>
      <ul className="findings">
        {KIND_ORDER.flatMap((kind) => findings.filter((f) => f.kind === kind)).map((f) => (
          <Finding key={f.id} finding={f} all={report.findings} />
        ))}
      </ul>
      {layer.id === 'dependencies' && report.related.length > 0 && (
        <ul className="related">
          {report.related.map((r) => (
            <li key={r.origin}>
              <a href={href('', { target: r.origin })}>Scan {new URL(r.origin).host}</a>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RawData({ report }: { report: ScanReport }) {
  const download = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `scan-${report.target.hostname}-${report.startedAt.slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  };
  return (
    <details className="raw">
      <summary>Every handshake the scanner made, and the certificates it received</summary>
      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>Handshake</th>
              <th>Answer</th>
              <th>Version</th>
              <th>Cipher suite</th>
              <th>Group</th>
              <th>Server signature</th>
            </tr>
          </thead>
          <tbody>
            {report.tls.probes.map((p) => (
              <tr key={p.id}>
                <td title={p.purpose}>{p.id.startsWith('group-') ? `only ${groupName(Number(p.id.slice(6)))}` : p.id.replaceAll('-', ' ')}</td>
                <td>{p.alert ? `alert ${p.alert}` : p.outcome.replaceAll('-', ' ')}</td>
                <td>{p.version === undefined ? '' : `TLS ${versionName(p.version)}`}</td>
                <td>{p.cipherSuite === undefined ? '' : cipherSuiteName(p.cipherSuite)}</td>
                <td>{p.group === undefined ? '' : groupName(p.group)}</td>
                <td>
                  {p.signatureScheme === undefined ? '' : signatureSchemeName(p.signatureScheme)}
                  {p.signatureValid === true && ' (verified)'}
                  {p.signatureValid === false && ' (INVALID)'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {report.certificates.map((c) => (
        <details key={c.fingerprint256} className="cert">
          <summary>
            Certificate {c.position}: {c.subject}
          </summary>
          <dl className="evidence">
            <div>
              <dt>Issuer</dt>
              <dd>{c.issuer}</dd>
            </div>
            <div>
              <dt>Key</dt>
              <dd>{c.key.algorithm}</dd>
            </div>
            <div>
              <dt>Signed with</dt>
              <dd>{c.signature.algorithm}</dd>
            </div>
            <div>
              <dt>Valid</dt>
              <dd>
                {c.notBefore.slice(0, 10)} to {c.notAfter.slice(0, 10)}
              </dd>
            </div>
            <div>
              <dt>SHA-256</dt>
              <dd>{c.fingerprint256}</dd>
            </div>
          </dl>
          <pre>{c.pem}</pre>
        </details>
      ))}
      <p>
        <button type="button" onClick={download}>
          Download the full report as JSON
        </button>
      </p>
    </details>
  );
}

export function Legend({ kinds = ['observation', 'inference', 'undetermined'] }: { kinds?: Kind[] }) {
  return (
    <ul className="legend">
      {kinds.map((kind) => (
        <li key={kind}>
          <KindMark kind={kind} />
          <span>{KIND_MEANING[kind]}</span>
        </li>
      ))}
    </ul>
  );
}

export function Report({ report, recorded }: { report: ScanReport; recorded?: boolean }) {
  const counts = (id: LayerId) => report.findings.filter((f) => f.layer === id).length;
  return (
    <article className="report">
      <header className="report-head">
        <h2>{new URL(report.target.url).host}</h2>
        <p className="fine">
          {recorded ? 'Recorded scan from ' : 'Scanned '}
          {when(report.startedAt)} at {report.network.address}. {report.tls.probes.length} handshakes in{' '}
          {report.durationMs < 1000 ? `${report.durationMs} ms` : `${(report.durationMs / 1000).toFixed(1)} s`}.
          {report.target.lab && ' A lab server on this machine.'}
        </p>
        {recorded && <p className="notice caution">This is a saved result from a real scan, not a live one. Servers change; run the scanner to see today’s answer.</p>}
      </header>

      {!report.reachable ? (
        <ul className="findings">
          {report.findings.map((f) => (
            <Finding key={f.id} finding={f} />
          ))}
        </ul>
      ) : (
        <>
          <ol className="layer-stack" aria-label="Layers of this sign-in, and what a quantum computer would change for each">
            {report.layers.map((layer) => (
              <LayerRow key={layer.id} layer={layer} count={counts(layer.id)} />
            ))}
          </ol>
          <Triad report={report} />
          <Legend />
          {report.layers.map((layer) => (
            <LayerSection key={layer.id} layer={layer} report={report} />
          ))}
          <section className="limits">
            <h3>What a scan from outside cannot see</h3>
            <ul>
              {NOT_OBSERVABLE.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <p>
              <a href={href('migrate')}>Finding these is where a migration starts.</a>
            </p>
          </section>
          <RawData report={report} />
        </>
      )}
    </article>
  );
}
