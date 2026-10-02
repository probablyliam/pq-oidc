/**
 * Where the stage's named anchors are. Two arrangements of the same stage:
 * a row (browser, network, server) for wide screens and a column for narrow
 * ones. The score never mentions coordinates, so it does not care which is
 * in use.
 */
import type { Anchor } from './engine.ts';

export interface Point {
  x: number;
  y: number;
}

export interface Rect extends Point {
  w: number;
  h: number;
}

export interface Layout {
  orientation: 'row' | 'column';
  width: number;
  height: number;
  /** Scale applied to every glyph, so text stays legible when the stage is drawn small. */
  glyphScale: number;
  panels: { browser: Rect; server: Rect; attacker?: Rect };
  /** The screen inside the browser panel. */
  screen: Rect;
  /** The two lanes of the network: the TLS handshake, and application data. */
  lanes: { tls: Rect; app: Rect };
  anchors: Record<Anchor, Point>;
}

const grid = (prefix: string, names: string[], xs: number[], y: number): [Anchor, Point][] => names.map((name, i) => [`${prefix}.${name}`, { x: xs[i]!, y }]);

function rowLayout(attacker: boolean): Layout {
  const bx = [74, 190, 306];
  const sx = [894, 1010, 1126];
  const anchors: [Anchor, Point][] = [
    ['b.screen', { x: 190, y: 92 }],
    ...grid('b', ['hold', 'hold2', 'trust'], bx, 196),
    ...grid('b', ['slot1', 'slot2', 'slot3'], bx, 256),
    ...grid('b', ['slot4', 'slot5', 'slot6'], bx, 316),
    ...grid('b', ['opA', 'op', 'opB'], [66, 190, 314], 436),
    ['b.tls', { x: 436, y: 106 }],
    ['b.tls2', { x: 436, y: 162 }],
    ['b.app', { x: 436, y: 300 }],
    ['s.tls', { x: 764, y: 106 }],
    ['s.tls2', { x: 764, y: 162 }],
    ['s.app', { x: 764, y: 300 }],
    ['tap.tls', { x: 600, y: 134 }],
    ['tap.app', { x: 600, y: 300 }],
    ...grid('s', ['slot1', 'slot2', 'slot3'], sx, 76),
    ...grid('s', ['slot4', 'slot5', 'slot6'], sx, 136),
    ...grid('s', ['slot7', 'slot8', 'slot9'], sx, 196),
    ...grid('s', ['work', 'work2'], [952, 1068], 300),
    ...grid('s', ['opA', 'op', 'opB'], [886, 1010, 1134], 436),
  ];
  if (attacker) {
    anchors.push(
      ['m.self', { x: 62, y: 668 }],
      ...grid('m', ['slot1', 'slot2', 'slot3'], [176, 292, 408], 632),
      ...grid('m', ['slot4', 'slot5', 'slot6'], [176, 292, 408], 692),
      ...grid('m', ['opA', 'op', 'opB'], [534, 660, 786], 668),
      ...grid('m', ['work1', 'work2'], [908, 1024], 632),
      ...grid('m', ['work3', 'work4'], [908, 1024], 692),
      ['m.out', { x: 1134, y: 662 }],
    );
  }
  return {
    orientation: 'row',
    width: 1200,
    height: attacker ? 762 : 552,
    glyphScale: 1,
    panels: { browser: { x: 8, y: 8, w: 364, h: 536 }, server: { x: 828, y: 8, w: 364, h: 536 }, attacker: attacker ? { x: 8, y: 566, w: 1184, h: 188 } : undefined },
    screen: { x: 28, y: 44, w: 324, h: 104 },
    lanes: { tls: { x: 372, y: 72, w: 456, h: 124 }, app: { x: 372, y: 266, w: 456, h: 68 } },
    anchors: Object.fromEntries(anchors),
  };
}

function columnLayout(attacker: boolean): Layout {
  const xs = [104, 300, 496];
  const anchors: [Anchor, Point][] = [
    ['b.screen', { x: 300, y: 100 }],
    ...grid('b', ['hold', 'hold2', 'trust'], xs, 208),
    ...grid('b', ['slot1', 'slot2', 'slot3'], xs, 284),
    ...grid('b', ['slot4', 'slot5', 'slot6'], xs, 360),
    ...grid('b', ['opA', 'op', 'opB'], [92, 300, 508], 468),
    ['b.tls', { x: 104, y: 596 }],
    ['b.tls2', { x: 260, y: 596 }],
    ['b.app', { x: 476, y: 596 }],
    ['s.tls', { x: 104, y: 764 }],
    ['s.tls2', { x: 260, y: 764 }],
    ['s.app', { x: 476, y: 764 }],
    ['tap.tls', { x: 182, y: 680 }],
    ['tap.app', { x: 476, y: 680 }],
    ...grid('s', ['slot1', 'slot2', 'slot3'], xs, 896),
    ...grid('s', ['slot4', 'slot5', 'slot6'], xs, 972),
    ...grid('s', ['slot7', 'slot8', 'slot9'], xs, 1048),
    ...grid('s', ['work', 'work2'], [190, 410], 1128),
    ...grid('s', ['opA', 'op', 'opB'], [92, 300, 508], 1240),
  ];
  if (attacker) {
    anchors.push(
      ['m.self', { x: 548, y: 1374 }],
      ...grid('m', ['slot1', 'slot2', 'slot3'], xs, 1456),
      ...grid('m', ['slot4', 'slot5', 'slot6'], xs, 1532),
      ...grid('m', ['opA', 'op', 'opB'], [92, 300, 508], 1644),
      ...grid('m', ['work1', 'work2', 'out'], xs, 1756),
      ...grid('m', ['work3', 'work4'], [104, 300], 1832),
    );
  }
  return {
    orientation: 'column',
    width: 600,
    height: attacker ? 1890 : 1326,
    glyphScale: 1.5,
    panels: { browser: { x: 6, y: 6, w: 588, h: 538 }, server: { x: 6, y: 816, w: 588, h: 504 }, attacker: attacker ? { x: 6, y: 1336, w: 588, h: 548 } : undefined },
    screen: { x: 30, y: 50, w: 540, h: 104 },
    lanes: { tls: { x: 14, y: 544, w: 336, h: 272 }, app: { x: 386, y: 544, w: 180, h: 272 } },
    anchors: Object.fromEntries(anchors),
  };
}

export function layoutFor(orientation: 'row' | 'column', attacker: boolean): Layout {
  return orientation === 'row' ? rowLayout(attacker) : columnLayout(attacker);
}

/** Every anchor either arrangement defines, for checking a score against. */
export function knownAnchors(attacker: boolean): Set<Anchor> {
  return new Set(['nowhere', 'wire', ...Object.keys(rowLayout(attacker).anchors)]);
}
