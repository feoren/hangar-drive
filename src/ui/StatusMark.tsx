// The tray icon of the current state, drawn large at the top of the main window and in the
// setup. Same geometry as the tray (tray/icons.ts), so people learn one picture.

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

/** The app's mark: the plain filled cloud, so it never claims a state. */
export function BrandMark({
  size = 20,
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
      viewBox={VIEW_BOX}
      aria-hidden="true"
      focusable="false"
    >
      <path d={CLOUD} fill="currentColor" />
    </svg>
  );
}
