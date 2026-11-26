// Names Windows cannot store (ADR 7, UX 7.2): checked while the person types a new name, and the
// suggestion that "Rename" starts with. The sync core makes the same decision in Rust; this copy
// only drives the rename field.

import type { NameReason } from "../backend/types";

const FORBIDDEN = /[<>:"/\\|?*]/;
// Built from code points so this file holds no raw control characters.
const CONTROL = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(31)}]`);
const CONTROL_ALL = new RegExp(CONTROL.source, "g");
const RESERVED = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i;
// A name ending in ".{GUID}" is a shell junction for Explorer (ADR 7): a folder of that name can
// lead the shell outside the sync folder, so the sync core refuses it on Windows.
const SHELL_JUNCTION = /\.(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})$/i;

function stem(name: string): string {
  const dot = name.indexOf(".");
  return dot === -1 ? name : name.slice(0, dot);
}

/** Why Windows refuses the name, or null when it is fine. */
export function windowsNameProblem(name: string): NameReason | null {
  const forbidden = FORBIDDEN.exec(name);
  if (forbidden) return { kind: "char", char: forbidden[0] };
  if (CONTROL.test(name)) return { kind: "control" };
  if (/[. ]$/.test(name)) return { kind: "trailing" };
  if (RESERVED.test(stem(name).trimEnd())) return { kind: "reserved", name: stem(name) };
  if (SHELL_JUNCTION.test(name)) return { kind: "reserved", name };
  return null;
}

/** A name close to the original that Windows accepts. */
export function suggestWindowsName(name: string): string {
  let result = name
    .replace(CONTROL_ALL, "")
    .replace(new RegExp(FORBIDDEN.source, "g"), " ")
    .replace(/ {2,}/g, " ")
    .replace(/[. ]+$/, "")
    .trim();
  if (RESERVED.test(stem(result))) {
    const dot = result.indexOf(".");
    result = dot === -1 ? `${result}_` : `${result.slice(0, dot)}_${result.slice(dot)}`;
  }
  result = result.replace(SHELL_JUNCTION, " $1");
  return result === "" ? "_" : result;
}
