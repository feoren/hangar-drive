// Names of devices (rule N5 of the security review): the server and the crypto crate refuse a
// name that is empty after trimming, that consists only of filler characters, or that has
// whitespace at its edges. The window trims before sending, so whitespace at the edges never
// reaches the backend; the two errors still have their own words for answers from the backend.

import type { NameError } from "../backend/types";

/** Hangul fillers that render as nothing (U+3164, U+115F, U+1160, U+FFA0). */
const FILLERS = new RegExp(`[${String.fromCharCode(0x3164, 0x115f, 0x1160, 0xffa0)}]`, "g");

/** The name as it is sent: whitespace at both ends removed. */
export function cleanName(input: string): string {
  return input.trim();
}

/** Why the name would be refused after cleaning, or null when it is fine. */
export function nameProblem(input: string): NameError | null {
  const clean = cleanName(input);
  return clean.replace(FILLERS, "").trim() === "" ? "blank" : null;
}

/** The same check without cleaning, as the backend applies it to what it receives. */
export function strictNameProblem(input: string): NameError | null {
  if (input.replace(FILLERS, "").trim() === "") return "blank";
  if (input !== input.trim()) return "edgeWhitespace";
  return null;
}
