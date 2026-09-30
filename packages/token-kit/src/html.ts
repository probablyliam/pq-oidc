/**
 * Tiny server-side HTML helpers shared by the provider and the demo apps, so
 * every page has the same look and the same escaping rules.
 */

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escapes text for use in HTML content and quoted attributes. Use it for every dynamic value. */
export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (ch) => ESCAPES[ch] ?? ch);
}

/** Tagged template that escapes interpolated values unless they are already `SafeHtml`. */
export class SafeHtml {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = strings[0] ?? '';
  values.forEach((value, i) => {
    out += renderValue(value) + (strings[i + 1] ?? '');
  });
  return new SafeHtml(out);
}

function renderValue(value: unknown): string {
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) return value.map(renderValue).join('');
  if (value === undefined || value === null || value === false) return '';
  return escapeHtml(value);
}

const BASE_CSS = `
:root {
  --bg: #f4f6f9; --surface: #ffffff; --surface-2: #eaeef3; --ink: #121a24; --ink-2: #4f5b69; --line: #cfd6de;
  --pq: #2f54eb; --pq-soft: #e4e9fd; --classical: #8a5a00; --classical-soft: #f5ecd9;
  --good: #1c7443; --good-soft: #dcf1e3; --bad: #b0292b; --bad-soft: #f9e1e1;
  --sans: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", sans-serif;
  --mono: "Cascadia Mono", ui-monospace, "SF Mono", Consolas, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d131a; --surface: #151d27; --surface-2: #1c2632; --ink: #e6ebf1; --ink-2: #9ba7b5; --line: #2b3845;
    --pq: #8aa2ff; --pq-soft: #1a2553; --classical: #e3aa48; --classical-soft: #33270f;
    --good: #5fca8c; --good-soft: #14311e; --bad: #f37d7d; --bad-soft: #3a1818;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.55 var(--sans); padding: 40px 16px 64px; }
main { max-width: 760px; margin: 0 auto; display: grid; gap: 20px; }
h1, h2, h3 { line-height: 1.2; margin: 0; text-wrap: balance; }
h1 { font-size: 1.75rem; } h2 { font-size: 1.2rem; } h3 { font-size: 1rem; }
p { margin: 0; }
a { color: var(--pq); text-underline-offset: 3px; }
code, .mono { font-family: var(--mono); font-size: 0.88em; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 600; color: var(--ink-2); font-size: 0.9rem; letter-spacing: 0.02em; }
.brand-mark { width: 22px; height: 22px; border-radius: 6px; background: var(--pq); display: grid; place-items: center; color: var(--surface); font: 700 11px var(--mono); }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 22px; display: grid; gap: 14px; min-width: 0; }
.muted { color: var(--ink-2); }
.small { font-size: 0.88rem; }
.badge { display: inline-flex; align-items: center; gap: 6px; font: 600 0.75rem var(--mono); padding: 3px 9px; border-radius: 999px; white-space: nowrap; }
.badge.pq { background: var(--pq-soft); color: var(--pq); }
.badge.classical { background: var(--classical-soft); color: var(--classical); }
.badge.good { background: var(--good-soft); color: var(--good); }
.badge.bad { background: var(--bad-soft); color: var(--bad); }
.notice { border-radius: 10px; padding: 12px 14px; font-size: 0.93rem; }
.notice.bad { background: var(--bad-soft); color: var(--bad); }
.notice.good { background: var(--good-soft); color: var(--good); }
.notice.info { background: var(--surface-2); }
form { display: grid; gap: 12px; }
label { display: grid; gap: 4px; font-size: 0.9rem; font-weight: 600; }
input { font: inherit; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--line); background: var(--bg); color: var(--ink); }
button, .button { font: 600 0.95rem var(--sans); padding: 10px 16px; border-radius: 8px; border: 1px solid var(--pq); background: var(--pq); color: var(--surface); cursor: pointer; text-decoration: none; display: inline-block; text-align: center; }
.button.secondary, button.secondary { background: transparent; color: var(--ink); border-color: var(--line); }
:focus-visible { outline: 2px solid var(--pq); outline-offset: 2px; }
.row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.row.spread { justify-content: space-between; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.92rem; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-2); font-weight: 600; font-size: 0.82rem; }
.stat { display: grid; gap: 2px; }
.stat b { font-size: 1.35rem; font-variant-numeric: tabular-nums; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
pre { margin: 0; background: var(--surface-2); padding: 12px; border-radius: 8px; overflow-x: auto; font: 0.8rem/1.5 var(--mono); white-space: pre-wrap; word-break: break-all; }
details summary { cursor: pointer; font-weight: 600; }
.bar { position: relative; height: 18px; background: var(--surface-2); border-radius: 4px; }
.bar > span { position: absolute; inset: 0 auto 0 0; border-radius: 4px; background: var(--pq); }
.bar > span.classical { background: var(--classical); }
.bar > i { position: absolute; top: -4px; bottom: -4px; border-left: 2px dashed var(--bad); }
footer { color: var(--ink-2); font-size: 0.82rem; text-align: center; }
`;

export interface PageOptions {
  title: string;
  /** Per-response CSP nonce; the inline stylesheet only runs if it matches. */
  nonce: string;
  body: SafeHtml;
  /** Page-specific CSS (e.g. computed bar widths). Goes in the same nonce'd stylesheet, so no inline style attributes are needed. */
  extraCss?: string;
}

export function renderPage({ title, nonce, body, extraCss = '' }: PageOptions): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style nonce="${escapeHtml(nonce)}">${BASE_CSS}${extraCss}</style>
</head>
<body>
<main>
${body.value}
</main>
</body>
</html>`;
}

/**
 * Security headers for the HTML pages we render ourselves. The CSP blocks all
 * scripts, allows only our nonce'd stylesheet, and forbids framing
 * (clickjacking protection for the login form).
 */
export function securityHeaders(nonce: string): Record<string, string> {
  return {
    'Content-Security-Policy': [
      "default-src 'none'",
      `style-src 'nonce-${nonce}'`,
      "img-src 'self' data:",
      // No form-action: browsers apply it to the redirects that follow a form
      // post, and the login form must be able to redirect back to the app.
      "frame-ancestors 'none'",
      "base-uri 'none'",
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  };
}
