import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// GitHub Pages serves the site from /<repo>/, so that build sets BASE_PATH=/pq-oidc/.
// In development the API runs on its own port; the dev server forwards to it so the
// page and the API share one origin, as they do when the API serves the built app.
const api = process.env.API_URL ?? 'http://localhost:8080';

export default defineConfig({
  base: process.env.BASE_PATH ?? '/',
  plugins: [react()],
  build: {
    target: 'es2022',
    // Never inline assets as data: URLs. The page's Content-Security-Policy allows fonts from this origin only.
    assetsInlineLimit: 0,
  },
  server: {
    proxy: {
      '/api': api,
    },
  },
});
