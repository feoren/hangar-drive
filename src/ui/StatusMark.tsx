// The status shape of the current state (tray/icons.ts), drawn large at the top of the main window
// and in the setup: one shape per state, so the state never rests on color alone.

import { useId } from "react";

import {
  CLOUD,
  GLYPHS,
  OUTLINE_WIDTH,
  SLASH,
  SLASH_GAP_WIDTH,
  VIEW_BOX,
  type Shape,
} from "../tray/icons";
import type { TrayIcon } from "../tray/trayModel";

function ShapeCut({ shape }: { readonly shape: Shape }) {
  switch (shape.type) {
    case "stroke":
      return (
        <path
          d={shape.d}
          fill="none"
          stroke="#000"
          strokeWidth={shape.width}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      );
    case "rect":
      return (
        <rect
          x={shape.x}
          y={shape.y}
          width={shape.width}
          height={shape.height}
          rx={shape.rx}
          fill="#000"
        />
      );
    case "circle":
      return <circle cx={shape.cx} cy={shape.cy} r={shape.r} fill="#000" />;
  }
}

export function StatusMark({
  icon,
  size = 44,
  className,
}: {
  readonly icon: TrayIcon;
  readonly size?: number;
  readonly className?: string;
}) {
  const id = useId();
  const glyph = GLYPHS[icon];
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox={VIEW_BOX}
      aria-hidden="true"
      focusable="false"
      data-icon={icon}
    >
      {glyph ? (
        <>
          <mask id={id}>
            <rect x="0" y="0" width="32" height="32" fill="#fff" />
            {glyph.map((shape, index) => (
              <ShapeCut key={index} shape={shape} />
            ))}
          </mask>
          <path d={CLOUD} fill="currentColor" mask={`url(#${id})`} />
        </>
      ) : (
        <>
          {icon === "offline" && (
            <mask id={id}>
              <rect x="0" y="0" width="32" height="32" fill="#fff" />
              <path d={SLASH} stroke="#000" strokeWidth={SLASH_GAP_WIDTH} strokeLinecap="round" />
            </mask>
          )}
          <path
            d={CLOUD}
            fill="none"
            stroke="currentColor"
            strokeWidth={OUTLINE_WIDTH}
            strokeLinecap="round"
            strokeLinejoin="round"
            mask={icon === "offline" ? `url(#${id})` : undefined}
          />
          {icon === "offline" && (
            <path
              d={SLASH}
              stroke="currentColor"
              strokeWidth={OUTLINE_WIDTH}
              strokeLinecap="round"
            />
          )}
        </>
      )}
    </svg>
  );
}

/**
 * The app's logo, the folded D of src-tauri/app-icon.svg (same paths), in its own colors in both
 * themes: it is the product's sign, not a state. Decorative: the app's name stands next to it.
 */
export function AppLogo({
  size = 22,
  className,
}: {
  readonly size?: number;
  readonly className?: string;
}) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 256 256"
      aria-hidden="true"
      focusable="false"
    >
      <rect width="256" height="256" rx="56" fill="var(--logo-tile)" />
      <path
        d="M40 72L80 58H160L216 114V158L174 200H40ZM80 98V160H158L176 142V130L144 98Z"
        fill="var(--logo-fold)"
        fillRule="evenodd"
      />
      <path d="M104 112H128V128H104ZM136 136H160V152H136Z" fill="var(--logo-squares)" />
    </svg>
  );
}
