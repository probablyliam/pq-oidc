/**
 * The two demo apps differ only in configuration:
 * - Legacy App's library only knows classical signatures, so it accepts ES256 only.
 * - PQ-Ready App has been upgraded. It accepts ML-DSA-65 and still accepts ES256,
 *   so it keeps working whichever key the provider uses for it during the migration.
 */
export interface RpPreset {
  clientId: string;
  appName: string;
  defaultPort: number;
  acceptedAlgs: string[];
  tagline: string;
}

export const PRESETS = {
  legacy: {
    clientId: 'legacy-app',
    appName: 'Legacy App',
    defaultPort: 3001,
    acceptedAlgs: ['ES256'],
    tagline: 'An app whose OIDC library predates post-quantum signatures.',
  },
  pq: {
    clientId: 'pq-app',
    appName: 'PQ-Ready App',
    defaultPort: 3002,
    acceptedAlgs: ['ML-DSA-65', 'ES256'],
    tagline: 'An app upgraded to verify ML-DSA-65 (RFC 9964) signatures.',
  },
} satisfies Record<string, RpPreset>;

export type PresetName = keyof typeof PRESETS;

export function isPresetName(value: unknown): value is PresetName {
  return value === 'legacy' || value === 'pq';
}
