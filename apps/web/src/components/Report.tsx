import { useState } from 'react';
import { NOT_OBSERVABLE } from '@pq-oidc/scan-core/report';
import type { Finding as ScanFinding, LayerSummary, ScanReport } from '@pq-oidc/scan-core/report';
import { cipherSuiteName, GROUPS, groupName, signatureSchemeName, versionName } from '@pq-oidc/scan-core/registry';
import { plainSummary } from '@pq-oidc/scan-core/summary';
import type { PlainAnswer } from '@pq-oidc/scan-core/summary';
import { Finding, KIND_MEANING, KindMark, learnHref } from './Finding.tsx';
import type { Kind } from './Finding.tsx';

/**
 * A scan result, in two depths. First, for anyone: one verdict and three
 * questions with short answers. Then, for someone who wants to check the
 * work: every finding with its evidence, behind "Technical details".
 */

function ago(iso: string): string {
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  if (minutes < 60 * 24) return `${Math.round(minutes / 60)} hour${Math.round(minutes / 60) === 1 ? '' : 's'} ago`;
  return `on ${new Date(iso).toLocaleDateString([], { dateStyle: 'medium' })}`;
}

function Answer({ answer }: { answer: PlainAnswer }) {
  return (
    <li className={`answer status-${answer.status}`}>
      <h3>{answer.question}</h3>
      <div>
        <p className="answer-short">
          <i className="mark" aria-hidden="true" />
          {answer.short}
        </p>
        <p className="answer-text">{answer.answer}</p>
        <p className="answer-more">
          {answer.technical && <code>{answer.technical}</code>}
          {answer.learn && <a href={learnHref(answer.learn)}>{answer.learn.view === 'token' ? 'Check a token from this site' : 'See how this works'}</a>}
        </p>
      </div>
    </li>
  );
}

/** The parts of a key-exchange group, drawn in the same grammar as the login explainer: dotted means post-quantum. */
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

const KIND_ORDER: ScanFinding['kind'][] = ['observation', 'inference', 'undetermined'];

function LayerSection({ layer, report }: { layer: LayerSummary; report: ScanReport }) {
  const findings = report.findings.filter((f) => f.layer === layer.id);
  const main = report.tls.probes.find((p) => p.id === 'pq-capable-client');
  return (
    <section className={`layer tone-${layer.tone}`}>
      <header>
        <h4>{layer.name}</h4>
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
              <a href={`#/?target=${encodeURIComponent(r.origin)}`}>Scan {new URL(r.origin).host}</a>
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
    <section className="raw">
      <h4>Every handshake the scanner made</h4>
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
    </section>
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

export interface ReportProps {
  report: ScanReport;
  /** A saved result from an earlier real scan, not a live one. */
  recorded?: boolean;
  /** How long a live result's link keeps working. */
  retentionHours?: number;
}

export function Report({ report, recorded, retentionHours }: ReportProps) {
  const [copied, setCopied] = useState(false);
  const summary = plainSummary(report);
  const host = new URL(report.target.url).host;

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
    } catch {
      // The link is in the address bar either way.
    }
  }

  return (
    <article className="report">
      <header className={`verdict verdict-${summary.verdict}`}>
        <p className="verdict-host">{host}</p>
        <h2>{summary.headline}</h2>
        <p className="verdict-why">{summary.explanation}</p>
        <p className="verdict-meta">
          {recorded ? `A saved result from a real scan ${ago(report.startedAt)}. Servers change.` : `Scanned ${ago(report.startedAt)}.`}
          {!recorded && retentionHours !== undefined && (
            <>
              {' '}
              <button type="button" className="link" onClick={() => void copyLink()}>
                {copied ? 'Link copied' : 'Copy a link to this result'}
              </button>{' '}
              (kept for {retentionHours} hours)
            </>
          )}
        </p>
      </header>

      {report.reachable && (
        <ol className="answers">
          {summary.answers.map((answer) => (
            <Answer key={answer.id} answer={answer} />
          ))}
        </ol>
      )}

      {summary.alsoNoticed.length > 0 && (
        <section className="also">
          <h3>Also noticed</h3>
          <ul>
            {summary.alsoNoticed.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p className="fine">These are problems today, with or without quantum computers.</p>
        </section>
      )}

      <details className="technical">
        <summary>Technical details</summary>
        <p className="fine">
          {report.tls.probes.length} TLS handshakes to {report.network.address} in {report.durationMs < 1000 ? `${report.durationMs} ms` : `${(report.durationMs / 1000).toFixed(1)} s`}. Every
          statement below is marked by how it is known.
        </p>
        <Legend />
        {report.reachable ? (
          report.layers.map((layer) => <LayerSection key={layer.id} layer={layer} report={report} />)
        ) : (
          <ul className="findings">
            {report.findings.map((f) => (
              <Finding key={f.id} finding={f} />
            ))}
          </ul>
        )}
        <section className="limits">
          <h4>What a scan from outside cannot see</h4>
          <ul>
            {NOT_OBSERVABLE.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
        {report.reachable && <RawData report={report} />}
      </details>
    </article>
  );
}
