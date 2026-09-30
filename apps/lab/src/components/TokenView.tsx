/** Shows a compact JWT with its header, claims and signature in different colours. */
export function TokenView({ token }: { token: string }) {
  const [header = '', payload = '', signature = ''] = token.split('.');
  return (
    <div className="token" aria-label="Encoded token">
      <span className="h">{header}</span>
      <span className="dot">.</span>
      <span className="p">{payload}</span>
      <span className="dot">.</span>
      <span className="s">{signature}</span>
    </div>
  );
}
