import { useEffect, useRef, useState } from 'react';

/**
 * Draws a JWT as a grid of squares, one square per byte, coloured by part
 * (header, claims, signature). Bytes past `limit` are drawn as outlines to show
 * what a browser throws away. Canvas keeps ~5,000 squares cheap to draw.
 */
export interface ByteMapProps {
  token: string;
  /** Squares per row; every map on the page should use the same value so sizes compare. */
  columns: number;
  /** Byte offset where a limit (e.g. the cookie limit) is reached. */
  limit?: number;
  label: string;
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Re-renders when the colour scheme changes, so canvas colours follow the theme. */
function useThemeVersion(): number {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const bump = () => setVersion((v) => v + 1);
    media.addEventListener('change', bump);
    const observer = new MutationObserver(bump);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => {
      media.removeEventListener('change', bump);
      observer.disconnect();
    };
  }, []);
  return version;
}

export function ByteMap({ token, columns, limit, label }: ByteMapProps) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const wrapper = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  const theme = useThemeVersion();

  useEffect(() => {
    const el = wrapper.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.floor(entry?.contentRect.width ?? 0)));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const c = canvas.current;
    if (!c || width === 0) return;
    const [header = '', payload = ''] = token.split('.');
    const total = token.length;
    // Whole-pixel squares avoid moiré; the map may end a few pixels short of the full width.
    const cell = Math.max(2, Math.floor(width / columns));
    const gap = cell >= 4 ? 1 : 0;
    const rows = Math.ceil(total / columns);
    const drawWidth = cell * columns;
    const height = rows * cell;
    const dpr = window.devicePixelRatio || 1;
    c.width = Math.floor(drawWidth * dpr);
    c.height = Math.floor(height * dpr);
    c.style.width = `${drawWidth}px`;
    c.style.height = `${height}px`;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, drawWidth, height);

    const colors = {
      header: cssVar('--part-header'),
      payload: cssVar('--part-payload'),
      signature: cssVar('--part-signature'),
      over: cssVar('--bad'),
    };
    const headerEnd = header.length + 1;
    const payloadEnd = headerEnd + payload.length + 1;

    for (let i = 0; i < total; i++) {
      const x = (i % columns) * cell;
      const y = Math.floor(i / columns) * cell;
      const color = i < headerEnd ? colors.header : i < payloadEnd ? colors.payload : colors.signature;
      if (limit !== undefined && i >= limit) {
        ctx.strokeStyle = colors.over;
        ctx.lineWidth = 1;
        ctx.strokeRect(x + 0.5, y + 0.5, cell - gap - 1, cell - gap - 1);
      } else {
        ctx.fillStyle = color;
        ctx.fillRect(x, y, cell - gap, cell - gap);
      }
    }
  }, [token, columns, limit, width, theme]);

  return (
    <div ref={wrapper} className="bytemap">
      <canvas ref={canvas} role="img" aria-label={label} />
    </div>
  );
}
