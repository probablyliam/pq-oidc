# 15. Given a site, find its sign-in and assess that

**Status:** accepted · 2026-10-02

## Context

The tool asks "is this login quantum-safe?", but a visitor typing `netflix.com` does not know where that site's login lives, and the first version answered "not a sign-in page". The owner: "if a user wanted to test how would they even know what to try".

## Decision

When the address given is a real page (HTTP 200, HTML) that is not a sign-in, the scanner looks for one, in this order, and the rest of the scan is about where it lands:

1. **The site's own link.** Anchors whose text says sign in / log in (or whose path looks like one) are collected from the page's HTML, best first; the two best are tried.
2. **The usual addresses**: `/login`, `/signin`, `/sign-in`, `/account/login`, `/auth/login`, `/users/sign_in`, on the origin the page ended up on.

At most three candidates are fetched. A candidate counts as the sign-in when it is a sign-in page by the same rules as any other (a password field, a username-first form, published metadata, or a sign-in address) or redirects to one. The report then describes **the sign-in's origin**: that is where a password would go, so its key exchange and certificate are the ones that matter. The address typed is kept (`entered`) and the report says "You entered netflix.com. Its sign-in is at www.netflix.com/login (one of the usual addresses)". When nothing is found, it says so and asks for the login's address; nothing is guessed.

Every candidate goes through the same policy, resolution and pinning as a typed address (ADR 0007): a link to a private address or another port is refused and listed as such, a plain-http link is never a candidate, and the search stops at the deadline.

No search happens for a page that was missing (404), errored, or redirected somewhere the policy refused: those are facts about the typed address and are reported as such, not papered over by a login found elsewhere.

## Alternatives

- **Guessing sub-domains** (`login.`, `accounts.`, `sso.`). Requests to hosts the visitor did not name and the site did not point to; left out.
- **Running the page's JavaScript** to find a script-built login. A browser engine in the worker, for a case the usual addresses already cover; left out (ADR 0013).

## Consequences

- Up to three extra fetches per scan, all to the site or where it links. The per-site rate limit (ADR 0014) bounds the total.
- Page reads are capped at 256 kB instead of 64 kB, because a home page's head can be longer than that and the link is in the body. A link's text is read through up to 2,000 characters of nested markup: GitHub's "Sign in" sits in spans whose class names alone run to hundreds of characters, and a 300-character window missed it.
- Verified on 2026-10-02 with one scan each: `netflix.com` → `www.netflix.com/ca/login`; `github.com` → `github.com/login`; `youtube.com` → `www.youtube.com/login`. Lab tests cover the link, the usual-address fallback, refused links, a sign-in on another origin, and that a sign-in given directly is not searched for.
