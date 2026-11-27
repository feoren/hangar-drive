// The status shapes (UX 6.1): one shape per state, never color alone. StatusMark.tsx draws them as
// the large status mark at the top of the main window and in the setup. The tray itself shows the
// app logo with a state dot, rasterized from src-tauri/app-icon.svg by src-tauri/build.rs.
//
// A cloud from three circles (left, top, right lobe) with a flat base. The glyph is cut out of the
// filled cloud, so it stays readable on any background: check (up to date), two arrows (syncing),
// two bars (paused), exclamation mark (needs you). Offline is the cloud outline with a slash,
// setup the plain outline. All shapes use `currentColor`, so the window's color tokens tint them.
// `iconBody` writes one shape as SVG markup, which the tests compare.

import type { TrayIcon } from "./trayModel";

export const TRAY_ICONS: readonly TrayIcon[] = [
  "attention",
  "paused",
  "offline",
  "syncing",
  "upToDate",
  "setup",
];

/** Square view box around the cloud (x 4 to 29, y 6 to 24), centered. */
export const VIEW_BOX = "2.5 1 28 28";

/** Outline of the cloud: left lobe (9,19) r5, top lobe (16,13) r7, right lobe (23,18) r6. */
export const CLOUD = "M9 24A5 5 0 0 1 9.07 14A7 7 0 0 1 22.93 12A6 6 0 0 1 23 24Z";

/** The slash of the offline icon. */
export const SLASH = "M5.5 7L24 25.5";

export type Shape =
  | { readonly type: "stroke"; readonly d: string; readonly width: number }
  | {
      readonly type: "rect";
      readonly x: number;
      readonly y: number;
      readonly width: number;
      readonly height: number;
      readonly rx: number;
    }
  | { readonly type: "circle"; readonly cx: number; readonly cy: number; readonly r: number };

/** What each icon cuts out of the filled cloud; null for the two outline icons. */
export const GLYPHS: Record<TrayIcon, readonly Shape[] | null> = {
  upToDate: [{ type: "stroke", d: "M11.5 18l3.2 3.2l6.3-6.7", width: 2.6 }],
  syncing: [
    { type: "stroke", d: "M13 22v-8.6M10.6 15.8l2.4-2.4l2.4 2.4", width: 2.2 },
    { type: "stroke", d: "M20 13.4v8.6M17.6 19.6l2.4 2.4l2.4-2.4", width: 2.2 },
  ],
  paused: [
    { type: "rect", x: 12.6, y: 13.5, width: 2.8, height: 8, rx: 1 },
    { type: "rect", x: 17.6, y: 13.5, width: 2.8, height: 8, rx: 1 },
  ],
  attention: [
    { type: "rect", x: 15.1, y: 11.8, width: 2.8, height: 7, rx: 1.4 },
    { type: "circle", cx: 16.5, cy: 21.6, r: 1.6 },
  ],
  offline: null,
  setup: null,
};

export const OUTLINE_WIDTH = 2.2;
/** Gap between the slash and the cloud outline, so they never merge into a blot at 16 px. */
export const SLASH_GAP_WIDTH = 5.4;

const ROUND = 'stroke-linecap="round" stroke-linejoin="round"';

function shapeSvg(shape: Shape): string {
  switch (shape.type) {
    case "stroke":
      return `<path d="${shape.d}" fill="none" stroke="#000" stroke-width="${String(shape.width)}" ${ROUND}/>`;
    case "rect":
      return `<rect x="${String(shape.x)}" y="${String(shape.y)}" width="${String(shape.width)}" height="${String(shape.height)}" rx="${String(shape.rx)}" fill="#000"/>`;
    case "circle":
      return `<circle cx="${String(shape.cx)}" cy="${String(shape.cy)}" r="${String(shape.r)}" fill="#000"/>`;
  }
}

const MASK_BASE = '<rect x="0" y="0" width="32" height="32" fill="#fff"/>';

/** The inner markup of one icon, without the `<svg>` element. */
export function iconBody(icon: TrayIcon): string {
  const glyph = GLYPHS[icon];
  const id = `cut-${icon}`;
  if (glyph) {
    return (
      `<mask id="${id}">${MASK_BASE}${glyph.map(shapeSvg).join("")}</mask>` +
      `<path d="${CLOUD}" fill="currentColor" mask="url(#${id})"/>`
    );
  }
  const cloud = `<path d="${CLOUD}" fill="none" stroke="currentColor" stroke-width="${String(OUTLINE_WIDTH)}" ${ROUND}`;
  if (icon === "setup") return `${cloud}/>`;
  return (
    `<mask id="${id}">${MASK_BASE}<path d="${SLASH}" stroke="#000" stroke-width="${String(SLASH_GAP_WIDTH)}" stroke-linecap="round"/></mask>` +
    `${cloud} mask="url(#${id})"/>` +
    `<path d="${SLASH}" stroke="currentColor" stroke-width="${String(OUTLINE_WIDTH)}" stroke-linecap="round"/>`
  );
}
