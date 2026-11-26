// Small line icons on a 20 px grid, 1.5 px strokes, `currentColor`. Decorative only: every icon
// sits next to a word or inside a control with its own accessible name.

import type { ReactNode } from "react";

interface IconProps {
  readonly size?: number;
  readonly className?: string;
}

function Svg({ size = 20, className, children }: IconProps & { readonly children: ReactNode }) {
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export function FolderIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M2.75 5.5a1.75 1.75 0 0 1 1.75-1.75h3.1l1.9 2h6a1.75 1.75 0 0 1 1.75 1.75v6.75a1.75 1.75 0 0 1-1.75 1.75h-11a1.75 1.75 0 0 1-1.75-1.75z" />
    </Svg>
  );
}

export function PlusIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M10 4.5v11M4.5 10h11" />
    </Svg>
  );
}

export function MenuIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3.5 5.5h13M3.5 10h13M3.5 14.5h13" />
    </Svg>
  );
}

export function ListIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M7.5 5.5h9M7.5 10h9M7.5 14.5h9M3.75 5.5h.5M3.75 10h.5M3.75 14.5h.5" />
    </Svg>
  );
}

export function GridIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="3.5" y="3.5" width="5.25" height="5.25" rx="1.2" />
      <rect x="11.25" y="3.5" width="5.25" height="5.25" rx="1.2" />
      <rect x="3.5" y="11.25" width="5.25" height="5.25" rx="1.2" />
      <rect x="11.25" y="11.25" width="5.25" height="5.25" rx="1.2" />
    </Svg>
  );
}

export function MoreIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="5" cy="10" r="0.6" fill="currentColor" strokeWidth="1.2" />
      <circle cx="10" cy="10" r="0.6" fill="currentColor" strokeWidth="1.2" />
      <circle cx="15" cy="10" r="0.6" fill="currentColor" strokeWidth="1.2" />
    </Svg>
  );
}

export function LaptopIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="4" y="4.75" width="12" height="8" rx="1.25" />
      <path d="M2.5 15.25h15" />
    </Svg>
  );
}

export function DesktopIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="2.75" y="3.75" width="14.5" height="9.5" rx="1.25" />
      <path d="M7.5 16.25h5M10 13.25v3" />
    </Svg>
  );
}

export function DevicesIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="2.75" y="4.25" width="10.5" height="7.5" rx="1.25" />
      <path d="M1.75 14.75h9" />
      <rect x="13.75" y="7.25" width="4.5" height="8.5" rx="1" />
    </Svg>
  );
}

export function GearIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="10" cy="10" r="2.5" />
      <path d="M10 2.75v2M10 15.25v2M17.25 10h-2M4.75 10h-2M15.13 4.87l-1.42 1.42M6.29 13.71l-1.42 1.42M15.13 15.13l-1.42-1.42M6.29 6.29 4.87 4.87" />
    </Svg>
  );
}

export function FileIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M5.25 2.75h6l3.5 3.5v10a1 1 0 0 1-1 1h-8.5a1 1 0 0 1-1-1v-12.5a1 1 0 0 1 1-1z" />
      <path d="M11 2.75v3.75h3.75" />
    </Svg>
  );
}

export function SearchIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="8.75" cy="8.75" r="5" />
      <path d="m12.5 12.5 4 4" />
    </Svg>
  );
}

export function ChevronIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m7.5 5 5 5-5 5" />
    </Svg>
  );
}

export function CheckIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m4.5 10.5 3.5 3.5 7.5-8" />
    </Svg>
  );
}

export function HelpIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="10" cy="10" r="7.25" />
      <path d="M7.9 7.75a2.15 2.15 0 0 1 4.15.75c0 1.5-2.05 1.9-2.05 3.25" />
      <circle cx="10" cy="14.25" r="0.4" fill="currentColor" />
    </Svg>
  );
}
