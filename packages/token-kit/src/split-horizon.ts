/**
 * Split-horizon access to an OpenID Connect provider.
 *
 * Browsers reach the provider at its public URL, but a server in the same
 * Docker network or Kubernetes cluster has to use an internal address
 * ("localhost:3000" inside a container is the container itself). This fetch:
 *  - sends requests for `publicBase` to `internalBase` instead;
 *  - rewrites the discovery document, which names the address it was fetched
 *    from, back to the public address, because the browser must be redirected
 *    to the public authorization endpoint. Back-channel calls to those URLs
 *    are rewritten again on the way out.
 */
export function rewritingFetch(publicBase: string, internalBase: string | undefined): typeof fetch {
  if (!internalBase || internalBase === publicBase) return fetch;
  return async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const target = url.startsWith(publicBase) ? internalBase + url.slice(publicBase.length) : url;
    const response = await fetch(target, init);
    if (!new URL(target).pathname.endsWith('/.well-known/openid-configuration') || !response.ok) return response;
    const body = (await response.text()).replaceAll(internalBase, publicBase);
    const headers = new Headers(response.headers);
    headers.delete('content-length'); // the body changed length and is already decoded
    headers.delete('content-encoding');
    return new Response(body, { status: response.status, statusText: response.statusText, headers });
  };
}
