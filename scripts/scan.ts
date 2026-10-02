/**
 * `npm run scan -- <url>`           scan one address from the command line
 * `npm run scan -- <url> --json`    print the full report as JSON
 *
 * The same scanner the service runs, without the service. Lab servers on this
 * machine can be scanned by listing them: SCAN_LAB_ORIGINS=https://localhost:9442
 */
import { DEFAULT_POLICY, parseLabOrigins, runScan, TargetRejected } from '@pq-oidc/scan-core';
import type { Finding, FindingKind } from '@pq-oidc/scan-core';

const args = process.argv.slice(2);
const input = args.find((a) => !a.startsWith('--'));
if (!input) {
  console.error('Usage: npm run scan -- <https URL> [--json]');
  process.exit(2);
}

const policy = { ...DEFAULT_POLICY, labOrigins: parseLabOrigins(process.env.SCAN_LAB_ORIGINS) };
const quiet = args.includes('--json');

try {
  const report = await runScan(input, { policy, onProgress: quiet ? undefined : (step) => console.error(`  … ${step}`) });
  if (quiet) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const LABEL: Record<FindingKind, string> = { observation: 'OBSERVED', inference: 'INFERRED', undetermined: 'UNDETERMINED' };
    console.log(`\n${report.target.url}  (${report.network.address}, ${report.durationMs} ms, ${report.tls.probes.length} handshakes)\n`);
    for (const layer of report.layers) {
      console.log(`${layer.name}: ${layer.headline}`);
      for (const finding of report.findings.filter((f: Finding) => f.layer === layer.id)) {
        console.log(`  [${LABEL[finding.kind]}] ${finding.title}`);
        for (const e of finding.evidence ?? []) console.log(`      ${e.label}: ${e.value}`);
      }
      console.log('');
    }
  }
} catch (error) {
  if (!(error instanceof TargetRejected)) throw error;
  console.error(`Refused (${error.code}): ${error.message}`);
  process.exitCode = 1;
}
