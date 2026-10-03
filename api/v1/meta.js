// What the web app asks first: is there a scan service here, and what does it allow.
// The engine version is read from the scanner's own file so the two never drift.
import { ENGINE_VERSION } from './scan.js';

export default {
  fetch() {
    return new Response(JSON.stringify({ service: 'pq-oidc', engine: ENGINE_VERSION, labOrigins: [], allowedPorts: [443, 8443] }), {
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  },
};
