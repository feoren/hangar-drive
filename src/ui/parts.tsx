// Small building blocks shared by many views.

import { useEffect, useState, type ReactNode } from "react";

import type { NumberRows as Rows } from "../backend/types";
import { spellOut } from "../domain/codes";
import { useT } from "../i18n";

/** How long a number check's confirm button holds back clicks (UX 5, ADR 6). */
export const ARM_DELAY_MS = 1000;

/**
 * A confirm button that takes no click for one second after it appears or `armKey` changes, so a
 * click meant for what was there before cannot confirm a number check. It looks disabled during
 * that second but keeps its name and its place in the tab order.
 */
export function ArmedButton({
  armKey,
  className = "button primary",
  onClick,
  children,
  autoFocus,
}: {
  readonly armKey: string;
  readonly className?: string;
  readonly onClick: () => void;
  readonly children: ReactNode;
  readonly autoFocus?: boolean;
}) {
  const [armedFor, setArmedFor] = useState<string | null>(null);
  useEffect(() => {
    const timer = setTimeout(() => {
      setArmedFor(armKey);
    }, ARM_DELAY_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [armKey]);
  const armed = armedFor === armKey;
  return (
    <button
      type="button"
      className={armed ? className : `${className} arming`}
      aria-disabled={!armed}
      data-autofocus={autoFocus ? true : undefined}
      onClick={() => {
        if (armed) onClick();
      }}
    >
      {children}
    </button>
  );
}

/** A line of feedback next to the control that caused it (UX: feedback where it happened). */
export function Feedback({
  tone = "ok",
  children,
  action,
}: {
  readonly tone?: "ok" | "error" | "info";
  readonly children: ReactNode;
  readonly action?: ReactNode;
}) {
  return (
    <p className={`feedback feedback-${tone}`} role={tone === "error" ? "alert" : "status"}>
      <span>{children}</span>
      {action}
    </p>
  );
}

/** Six groups of five digits, laid out three by two so the eye compares group by group. */
export function NumberRows({ rows, label }: { readonly rows: Rows; readonly label: string }) {
  const t = useT();
  return (
    <div className="number-rows" role="group" aria-label={label}>
      {rows.groups.map((group, index) => (
        <span
          key={index}
          className="number-group"
          role="img"
          aria-label={t("safety.group", { index: index + 1, digits: spellOut(group) })}
        >
          {group}
        </span>
      ))}
    </div>
  );
}

/** The recovery code: eight groups of four, large and selectable, read group by group. */
export function CodeGroups({
  groups,
  label,
}: {
  readonly groups: readonly string[];
  readonly label: string;
}) {
  const t = useT();
  return (
    <div className="code-groups" role="group" aria-label={label}>
      {groups.map((group, index) => (
        <span
          key={index}
          className="code-group"
          role="img"
          aria-label={t("recovery.groupLabel", { index: index + 1, chars: spellOut(group) })}
        >
          {group}
        </span>
      ))}
    </div>
  );
}

/**
 * A path truncated in the middle: the start gives way, the last part (the folder's own name)
 * stays. The full path is the tooltip; screen readers get it from the row's name.
 */
export function PathText({
  path,
  className,
}: {
  readonly path: string;
  readonly className?: string;
}) {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  const head = cut >= 0 ? path.slice(0, cut + 1) : "";
  const tail = cut >= 0 ? path.slice(cut + 1) : path;
  return (
    <span className={className ? `path ${className}` : "path"} title={path}>
      <span className="path-head">{head}</span>
      <span className="path-tail">{tail}</span>
    </span>
  );
}

/** An SVG document as a `data:` URL for an `<img>` (the CSP allows `img-src data:`). */
export function svgDataUrl(svg: string): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

/**
 * A QR code from the backend's SVG document, shown as an image: the document never becomes
 * markup of the page, so nothing in it can run or style the window.
 */
export function QrCode({
  svg,
  label,
  size = 168,
}: {
  readonly svg: string;
  readonly label: string;
  readonly size?: number;
}) {
  return <img className="qr" src={svgDataUrl(svg)} width={size} height={size} alt={label} />;
}

/** A small, calm busy indicator for loading lists; screen readers hear the label once. */
export function Loading() {
  const t = useT();
  return (
    <p className="loading" role="status">
      {t("common.loading")}
    </p>
  );
}
