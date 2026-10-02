/**
 * Saved reports from real scans, shown when there is no scan service behind
 * the page (the static build) and as examples everywhere else. Each is the
 * unedited output of `npm run scan -- <url> --json` and carries its own date.
 */
import type { ScanReport } from '@pq-oidc/scan-core/report';
import cloudflare from './cloudflare.json' with { type: 'json' };
import github from './github.json' with { type: 'json' };
import google from './google.json' with { type: 'json' };
import labClassical from './lab-classical.json' with { type: 'json' };
import labHybrid from './lab-hybrid.json' with { type: 'json' };
import labPq from './lab-pq.json' with { type: 'json' };
import labTls12 from './lab-tls12.json' with { type: 'json' };
import microsoft from './microsoft.json' with { type: 'json' };

export interface Recorded {
  id: string;
  label: string;
  report: ScanReport;
}

const entry = (id: string, label: string, report: unknown): Recorded => ({ id, label, report: report as ScanReport });

export const RECORDED: Recorded[] = [
  entry('google', 'accounts.google.com', google),
  entry('microsoft', 'login.microsoftonline.com', microsoft),
  entry('cloudflare', 'www.cloudflare.com', cloudflare),
  entry('github', 'github.com', github),
  entry('lab-pq', 'Lab server: post-quantum throughout', labPq),
  entry('lab-hybrid', 'Lab server: hybrid key exchange', labHybrid),
  entry('lab-classical', 'Lab server: classical', labClassical),
  entry('lab-tls12', 'Lab server: TLS 1.2 only', labTls12),
];
