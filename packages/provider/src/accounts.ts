import { createHash, timingSafeEqual } from 'node:crypto';
import type { FindAccount } from 'oidc-provider';

/**
 * Demo accounts. These are fictional people with a published password, so the
 * public demo can be tried by anyone. A real provider would call a user store.
 */
export const DEMO_PASSWORD = 'quantum-safe';

export interface DemoAccount {
  id: string;
  profile: {
    name: string;
    given_name: string;
    family_name: string;
    email: string;
    email_verified: boolean;
  };
}

export const DEMO_ACCOUNTS: readonly DemoAccount[] = [
  {
    id: 'alice',
    profile: {
      name: 'Alice Nakamura',
      given_name: 'Alice',
      family_name: 'Nakamura',
      email: 'alice.nakamura@example.com',
      email_verified: true,
    },
  },
  {
    id: 'bob',
    profile: {
      name: 'Bob Okafor',
      given_name: 'Bob',
      family_name: 'Okafor',
      email: 'bob.okafor@example.com',
      email_verified: true,
    },
  },
];

/** Compares secrets in constant time so response timing doesn't leak how much of a guess was right. */
function safeEqual(a: string, b: string): boolean {
  const digestA = createHash('sha256').update(a).digest();
  const digestB = createHash('sha256').update(b).digest();
  return timingSafeEqual(digestA, digestB);
}

export function checkCredentials(username: string, password: string): DemoAccount | undefined {
  const account = DEMO_ACCOUNTS.find((a) => a.id === username.trim().toLowerCase());
  const passwordOk = safeEqual(password, DEMO_PASSWORD);
  return account && passwordOk ? account : undefined;
}

/** oidc-provider calls this to turn an account ID into the claims it puts in tokens. */
export const findAccount: FindAccount = (_ctx, id) => {
  const account = DEMO_ACCOUNTS.find((a) => a.id === id);
  if (!account) return undefined;
  return {
    accountId: account.id,
    claims: () => ({ sub: account.id, ...account.profile }),
  };
};
