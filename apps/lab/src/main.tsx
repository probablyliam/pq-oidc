import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import './styles.css';
import './looks.css';

// TEMPORARY: ?look=b or ?look=c previews an alternative visual direction (see looks.css).
const LOOK_FONTS: Record<string, string> = {
  b: 'family=Barlow:wght@400;600;700&family=Barlow+Semi+Condensed:wght@600;700&family=JetBrains+Mono:wght@400;600',
  c: 'family=Archivo:wdth,wght@100..125,400..900&family=JetBrains+Mono:wght@400;600',
};
const look = new URLSearchParams(window.location.search).get('look') ?? '';
if (LOOK_FONTS[look]) {
  document.documentElement.dataset.look = look;
  const fonts = document.createElement('link');
  fonts.rel = 'stylesheet';
  fonts.href = `https://fonts.googleapis.com/css2?${LOOK_FONTS[look]}&display=swap`;
  document.head.append(fonts);
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
