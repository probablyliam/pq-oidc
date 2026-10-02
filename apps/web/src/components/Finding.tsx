import type { LearnLink } from '@pq-oidc/scan-core/report';
import { href } from '../router.ts';

/**
 * One finding, drawn according to how it is known. The three kinds look
 * different without relying on colour: a solid rule for something observed, a
 * dashed rule for something inferred, hatching for something not determined.
 */
export type Kind = 'observation' | 'inference' | 'undetermined' | 'simulation' | 'model' | 'real';

export interface FindingLike {
  id: string;
  kind: 'observation' | 'inference' | 'undetermined';
  tone: 'good' | 'caution' | 'bad' | 'neutral';
  title: string;
  detail: string;
  evidence?: { label: string; value: string }[];
  basedOn?: string[];
  learn?: LearnLink;
}

export const KIND_LABEL: Record<Kind, string> = {
  observation: 'Observed',
  inference: 'Inferred',
  undetermined: 'Could not determine',
  simulation: 'Conceptual simulation',
  model: 'Simplified model',
  real: 'Real computation',
};

export const KIND_MEANING: Record<Kind, string> = {
  observation: 'A real observation: read directly off the connection or from a document the service published.',
  inference: 'An inference: a conclusion drawn from observations, with the reasoning shown.',
  undetermined: 'Something the scanner looked for and could not establish.',
  simulation: 'An illustration of something that cannot be run today, such as a quantum attack.',
  model: 'A simplified version of a real protocol, run with real cryptography.',
  real: 'An operation that actually ran in your browser.',
};

export function KindMark({ kind }: { kind: Kind }) {
  return (
    <span className={`kind kind-${kind}`} title={KIND_MEANING[kind]}>
      <i aria-hidden="true" />
      {KIND_LABEL[kind]}
    </span>
  );
}

export function learnHref(link: LearnLink): string {
  if (link.view === 'login') return href('learn', { mode: link.mode, at: link.landmark, attacker: link.attacker });
  return href(link.view);
}

export function Finding({ finding, all }: { finding: FindingLike; all?: FindingLike[] }) {
  const bases = (finding.basedOn ?? []).map((id) => all?.find((f) => f.id === id)).filter((f) => f !== undefined);
  return (
    <li className={`finding kind-${finding.kind} tone-${finding.tone}`} id={`finding-${finding.id}`}>
      <KindMark kind={finding.kind} />
      <h4>{finding.title}</h4>
      <p>{finding.detail}</p>
      {bases.length > 0 && (
        <p className="rests-on">
          Rests on:{' '}
          {bases.map((base, i) => (
            <span key={base.id}>
              {i > 0 && '; '}
              <a href={`#finding-${base.id}`} onClick={(event) => scrollToFinding(event, base.id)}>
                {base.title}
              </a>
            </span>
          ))}
        </p>
      )}
      {finding.evidence && finding.evidence.length > 0 && (
        <details>
          <summary>{finding.kind === 'observation' ? 'Evidence' : 'Details'}</summary>
          <dl className="evidence">
            {finding.evidence.map((item, i) => (
              <div key={i}>
                <dt>{item.label}</dt>
                <dd>{item.value}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
      {finding.learn && (
        <a className="learn-link" href={learnHref(finding.learn)}>
          {finding.learn.label}
        </a>
      )}
    </li>
  );
}

/** In-page jump that leaves the route (which lives in the hash) alone. */
function scrollToFinding(event: React.MouseEvent, id: string) {
  event.preventDefault();
  const target = document.getElementById(`finding-${id}`);
  target?.scrollIntoView({ block: 'center' });
  target?.classList.add('flash');
  window.setTimeout(() => target?.classList.remove('flash'), 1200);
}
