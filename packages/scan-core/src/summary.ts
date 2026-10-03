/**
 * A scan report in plain words: one verdict and three questions an ordinary
 * person would actually ask, each with a short answer. Everything here is
 * derived from the report's layers by rules written out below, so the
 * technical findings underneath always say why (ADR 0012).
 *
 *   Can a recording of this connection be read later?   key exchange
 *   Can someone pretend to be this site?                certificate
 *   Can someone fake a sign-in?                         token signatures
 *
 * The verdict is a word, not a number: "not quantum-safe" if recordings can
 * be read later (the one risk that starts today), "partly" if only the
 * identity checks are still classical, "quantum-safe" if nothing visible is.
 *
 * Pure, and free of Node APIs: the web app computes it when it draws a report.
 */
import type { LayerId, LearnLink, PageSummary, QuantumExposure, ScanReport } from './report.ts';

/** safe: fine against a quantum computer. later: at risk once one exists. now: at risk from today. */
export type PlainStatus = 'safe' | 'later' | 'now' | 'unknown';

export interface PlainAnswer {
  id: 'recording' | 'impersonation' | 'sign-in';
  layer: LayerId;
  question: string;
  /** The answer in a few words. */
  short: string;
  status: PlainStatus;
  /** The answer in a sentence or two. */
  answer: string;
  /** The algorithm, for people who want its name. */
  technical: string;
  learn?: LearnLink;
}

export type Verdict = 'not-safe' | 'partly' | 'safe' | 'unknown';

/** What the address is, in one sentence: the scanner looks at any address, and a login is only one kind. */
export interface PlainPage {
  kind: PageSummary['kind'];
  /** The full account of what the address is, for the technical details. */
  note: string;
  /** One short line for the top of the result: where the login was found, or that none was. Nothing when the address given was itself the login. */
  line?: string;
  /** Where visitors are sent on to, when that is another origin. */
  leadsTo?: string;
}

export interface PlainSummary {
  verdict: Verdict;
  headline: string;
  explanation: string;
  answers: PlainAnswer[];
  /** Absent when the address could not be fetched, or the report predates the check. */
  page?: PlainPage;
  /** Problems that have nothing to do with quantum computers, as plain sentences. */
  alsoNoticed: string[];
}

/** `host` is the one the report is about; `entered` is the one typed, when that differs. */
function describePage(page: PageSummary, host: string, entered?: string): PlainPage {
  const elsewhere = page.leadsTo ? new URL(page.leadsTo).host : undefined;
  const seen = {
    'password-field': 'it asks for a password',
    'username-field': 'it asks for a username first',
    address: 'the address is a sign-in endpoint; its form is built by script',
    metadata: 'it publishes how it signs people in',
  }[page.how ?? 'password-field'];
  const you = entered ? `You entered ${entered}. ` : '';
  const where = page.found ? `${host}${new URL(page.found.url).pathname.replace(/\/$/, '')}` : host;
  const by = page.found ? ` (${{ link: 'the site’s own Sign in link', convention: 'one of the usual addresses', redirect: 'where the site sends visitors' }[page.found.by]})` : '';
  const located = page.found !== undefined || entered !== undefined;
  const note = {
    'sign-in-service': located
      ? `${you}Its sign-in is at ${where}${by}, a sign-in service. A scan can also check how it signs you in, not just the connection.`
      : 'A sign-in service: other sites send people here to log in. A scan can also check how it signs you in, not just the connection.',
    'sign-in-page': located ? `${you}Its sign-in is at ${where}${by}: ${seen}.` : `A sign-in page: ${seen}.`,
    'leads-to-sign-in': `${you}This address sends visitors on to sign in at ${elsewhere}.`,
    other: `${you}Not a sign-in page, and no sign-in was found at the usual addresses${elsewhere ? `; it sends visitors on to ${elsewhere}` : ''}. If the site has a login, paste its address. A scan can still check the connection and the site’s identity below.`,
  }[page.kind];
  const line = page.found ? `Found login: ${where}` : page.kind === 'other' ? 'No login found here' : undefined;
  return { kind: page.kind, note, line, leadsTo: page.leadsTo };
}

const strip = (headline: string) => headline.replace(/^(Classical|Hybrid|Post-quantum|Migrating): /, '');

export function plainSummary(report: ScanReport): PlainSummary {
  const layer = (id: LayerId) => report.layers.find((l) => l.id === id);
  const exposure = (id: LayerId): QuantumExposure => layer(id)?.exposure ?? 'undetermined';
  const technical = (id: LayerId) => strip(layer(id)?.headline ?? '');
  const learn = (id: string) => report.findings.find((f) => f.id === id)?.learn;

  // ---- Can a recording be read later? The key exchange decides.
  const kex = exposure('key-establishment');
  const recording: PlainAnswer = {
    id: 'recording',
    layer: 'key-establishment',
    question: 'If someone records this connection today, can they read it later?',
    technical: technical('key-establishment'),
    learn: learn('kex.exposure'),
    ...(kex === 'harvest-now-decrypt-later'
      ? {
          status: 'now',
          short: 'Yes',
          answer:
            'The site agrees its encryption keys with an older method that a large quantum computer will be able to undo. Someone who saves a copy of your connection today could open it once such a computer exists.',
        }
      : kex === 'depends-on-client'
        ? {
            status: 'safe',
            short: 'No, in an up-to-date browser',
            answer: 'With browsers that support it, the site uses a quantum-safe key exchange. Older browsers and apps still get the old kind, and their connections could be read later.',
          }
        : kex === 'no-known-attack'
          ? { status: 'safe', short: 'No', answer: 'Every connection to this site uses a quantum-safe key exchange.' }
          : { status: 'unknown', short: 'Could not tell', answer: 'The scanner could not complete a connection to find out.' }),
  };

  // ---- Can someone pretend to be this site? The certificate decides.
  const cert = exposure('server-authentication');
  const impersonation: PlainAnswer = {
    id: 'impersonation',
    layer: 'server-authentication',
    question: 'Can someone pretend to be this site?',
    technical: technical('server-authentication').replace(/ certificate$/, ''),
    learn: learn('auth.exposure'),
    ...(cert === 'forgery-once-quantum'
      ? {
          status: 'later',
          short: 'Not today',
          answer:
            'The site proves it is the real one with a kind of signature a quantum computer could fake, once one exists. Nothing recorded today is affected. No public website can fix this yet: browsers do not accept quantum-safe certificates.',
        }
      : cert === 'no-known-attack'
        ? { status: 'safe', short: 'No', answer: 'Its certificate uses a quantum-safe signature, so not even a quantum computer could fake it.' }
        : { status: 'unknown', short: 'Could not tell', answer: 'The scanner could not read the site’s certificate.' }),
  };

  // ---- Can someone fake a sign-in? The token signature decides, when it can be seen at all.
  const token = exposure('token-signing');
  const page = report.reachable && report.page ? describePage(report.page, new URL(report.target.url).host, report.entered ? new URL(report.entered.url).host : undefined) : undefined;
  const migrating = layer('token-signing')?.headline.startsWith('Migrating') ?? false;
  const signIn: PlainAnswer = {
    id: 'sign-in',
    layer: 'token-signing',
    question: 'Can someone fake a sign-in?',
    technical: token === 'undetermined' ? '' : technical('token-signing'),
    learn: learn(token === 'undetermined' ? 'token.undetermined' : 'token.exposure'),
    ...(token === 'forgery-once-quantum'
      ? {
          status: 'later',
          short: migrating ? 'Not today, and it has started switching' : 'Not today',
          answer: migrating
            ? 'When you sign in, the service vouches for you with a signature. It has added a quantum-safe key next to its old one, so it is partway through the change. The old kind could be faked once a quantum computer exists.'
            : 'When you sign in, the service vouches for you with a signature that a quantum computer could fake, once one exists. Nothing recorded today is affected.',
        }
      : token === 'no-known-attack'
        ? { status: 'safe', short: 'No', answer: 'Sign-ins are vouched for with a quantum-safe signature.' }
        : page?.kind === 'other'
          ? {
              status: 'unknown',
              short: 'No sign-in found',
              answer: 'Nothing at this address signs anyone in, so there is nothing to check here. If the site has a login, scan the address of its login page.',
            }
          : {
            status: 'unknown',
            short: 'Cannot tell from outside',
            answer: 'This site does not publish how it signs sign-ins, so a scan cannot see it. If the site gives you a token, the token checker can.',
          }),
  };

  const answers = [recording, impersonation, signIn];
  let verdict: Verdict;
  let headline: string;
  let explanation: string;
  if (!report.reachable || recording.status === 'unknown') {
    verdict = 'unknown';
    headline = 'Could not check';
    explanation = report.reachable ? 'The site answered, but not in a way the scanner could read.' : 'The scanner could not connect to this address.';
  } else if (recording.status === 'now') {
    verdict = 'not-safe';
    headline = 'Not quantum-safe';
    explanation = 'What you send to this site today could be read in the future, once large quantum computers exist.';
  } else if (impersonation.status === 'safe' && signIn.status !== 'later') {
    verdict = 'safe';
    headline = 'Quantum-safe';
    explanation = signIn.status === 'unknown' ? 'Everything a scan can see is quantum-safe. How it signs sign-ins is not visible from outside.' : 'Nothing a scan can see here could be broken by a quantum computer.';
  } else {
    verdict = 'partly';
    headline = 'Partly quantum-safe';
    explanation = 'What you send is protected from future quantum computers. The way the site proves who it is has not changed yet, which only matters once such computers exist.';
  }

  // Things that are wrong today, quantum computers or not. Their titles are already plain sentences.
  const today = ['kex.large-hello', 'kex.tls12', 'auth.validity', 'auth.trust', 'auth.proof', 'http.hsts', 'http.plain', 'http.cookies'];
  const alsoNoticed = report.findings.filter((f) => today.includes(f.id) && (f.tone === 'bad' || (f.tone === 'caution' && f.kind === 'observation'))).map((f) => f.title);

  return { verdict, headline, explanation, answers, page, alsoNoticed };
}
