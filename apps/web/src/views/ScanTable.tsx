import type { LayerId, LayerSummary } from '@pq-oidc/scan-core/report';
import type { ReactNode } from 'react';

export interface ScanRowData {
  key: string;
  link: string;
  host: string;
  when: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed';
  layers?: LayerSummary[];
  /** A control at the start of the row, e.g. a checkbox for comparing. */
  lead?: ReactNode;
}

const COLUMNS: [LayerId, string][] = [
  ['key-establishment', 'Key exchange'],
  ['server-authentication', 'Certificate'],
  ['token-signing', 'Token signing'],
];

const day = (iso: string) => new Date(iso).toLocaleDateString([], { dateStyle: 'medium' });

/** One row per scan, one column per layer that matters most. */
export function ScanTable({ rows, lead }: { rows: ScanRowData[]; lead?: string }) {
  return (
    <div className="scroll-x">
      <table className="scan-list">
        <thead>
          <tr>
            {lead && <th>{lead}</th>}
            <th>Address</th>
            {COLUMNS.map(([, name]) => (
              <th key={name}>{name}</th>
            ))}
            <th>Scanned</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              {lead && <td>{row.lead}</td>}
              <td className="host">
                <a href={row.link}>{row.host}</a>
              </td>
              {row.status === 'succeeded' && row.layers ? (
                COLUMNS.map(([id]) => {
                  const layer = row.layers!.find((l) => l.id === id);
                  return (
                    <td key={id} className={layer?.exposure === 'undetermined' ? 'unknown' : `tone-${layer?.tone}`}>
                      {layer?.headline ?? ''}
                    </td>
                  );
                })
              ) : (
                <td colSpan={COLUMNS.length} className="unknown">
                  {row.status === 'failed' ? 'The scan failed' : 'In progress'}
                </td>
              )}
              <td>{day(row.when)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
