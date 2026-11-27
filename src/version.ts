// Version scheme Major.Minor.Revision-Build, e.g. 0.1.0-12 (docs/wiki/pages/decisions/0002-version-scheme.md).
// Internally (Tauri, Cargo, npm) the build number is SemVer build metadata after "+", because the
// Windows installer takes the four-part file version 0.1.0.12 from it; a "-" is displayed instead.

export interface AppVersion {
  readonly major: number;
  readonly minor: number;
  readonly revision: number;
  readonly build: number | null;
}

const PATTERN = /^v?(\d+)\.(\d+)\.(\d+)(?:[+-](\d+))?$/;

/** Reads "0.1.0+12", "0.1.0-12", "v0.1.0" or "0.1.0"; anything else gives `null`. */
export function parseVersion(text: string): AppVersion | null {
  const match = PATTERN.exec(text.trim());
  if (!match) return null;
  const [, major, minor, revision, build] = match;
  if (major === undefined || minor === undefined || revision === undefined) return null;
  return {
    major: Number(major),
    minor: Number(minor),
    revision: Number(revision),
    build: build === undefined ? null : Number(build),
  };
}

/** Display form "0.1.0-12"; without a build number "0.1.0". Unreadable input stays as it is. */
export function formatVersion(text: string): string {
  const version = parseVersion(text);
  if (!version) return text;
  const base = `${String(version.major)}.${String(version.minor)}.${String(version.revision)}`;
  return version.build === null ? base : `${base}-${String(version.build)}`;
}

/**
 * Adds the build number when the version carries none (a development build only knows X.Y.Z).
 * A version with its own build number stays unchanged, as does unreadable input.
 */
export function withBuild(text: string, build: number | null): string {
  const version = parseVersion(text);
  if (!version || version.build !== null || build === null) return text;
  return `${formatVersion(text)}+${String(build)}`;
}

/**
 * Orders by X.Y.Z only: every release raises one of them, so the build number never decides.
 * Unreadable versions sort before readable ones.
 */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return Number(left !== null) - Number(right !== null);
  return left.major - right.major || left.minor - right.minor || left.revision - right.revision;
}

/**
 * Splits for display with a badge, as in Hangar: the number "0.1.0-12" and whether "beta" belongs
 * to it. While the major version is 0 the app counts as beta; from 1.0.0 on the badge goes.
 */
export function versionParts(text: string): { number: string; beta: boolean } {
  const version = parseVersion(text);
  return { number: formatVersion(text), beta: version !== null && version.major === 0 };
}
