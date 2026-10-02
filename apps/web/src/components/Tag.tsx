/**
 * The small mark beside an algorithm's name that says what kind of
 * cryptography it is. Used wherever an algorithm is named, so the three words
 * mean the same thing on every page.
 */
export type TagKind = 'classical' | 'PQC' | 'symmetric';

export const TAG_MEANING: Record<TagKind, string> = {
  classical: 'Classical public-key cryptography: a large quantum computer could break it.',
  PQC: 'Post-quantum cryptography: designed to resist quantum computers.',
  symmetric: 'Symmetric cryptography: quantum computers only weaken it slightly.',
};

export function Tag({ kind }: { kind: TagKind }) {
  return (
    <span className={`tag tag-${kind.toLowerCase()}`} title={TAG_MEANING[kind]}>
      {kind}
    </span>
  );
}

/** The kind of a public-key algorithm, from its name. */
export const tagFor = (algorithm: string): TagKind => (/ML-KEM|ML-DSA|SLH-DSA|Kyber|Dilithium|Falcon/i.test(algorithm) ? 'PQC' : 'classical');
