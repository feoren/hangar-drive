/// <reference types="node" />
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { LANGUAGES } from "./i18n";
import { compareVersions, formatVersion } from "./version";

// Rule "the code always carries the upcoming version" (ADR 0002): every version file names the same
// version, and its X.Y.Z is the highest entry in the changelog. The manifests are read as text, so
// no build step stands in between; this test only reads them.

function read(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function jsonVersion(path: string): string {
  const parsed: unknown = JSON.parse(read(path));
  if (typeof parsed === "object" && parsed !== null && "version" in parsed) {
    const { version } = parsed;
    if (typeof version === "string") return version;
  }
  throw new Error(`${path}: no version`);
}

/** The body of one TOML table, up to the next table header. */
function tomlTable(toml: string, name: string): string | null {
  const lines = toml.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === `[${name}]`);
  if (start < 0) return null;
  const end = lines.findIndex((line, index) => index > start && /^\s*\[/.test(line));
  return lines.slice(start + 1, end < 0 ? undefined : end).join("\n");
}

function tomlString(table: string, key: string): string | null {
  return new RegExp(`^${key}\\s*=\\s*"([^"]+)"`, "m").exec(table)?.[1] ?? null;
}

const rootCargo = read("Cargo.toml");

function workspaceMembers(): string[] {
  const workspace = tomlTable(rootCargo, "workspace");
  const list = workspace === null ? undefined : /^members\s*=\s*\[([^\]]*)\]/m.exec(workspace)?.[1];
  if (list === undefined) throw new Error("Cargo.toml: no workspace members");
  return [...list.matchAll(/"([^"]+)"/g)].flatMap((match) => (match[1] ? [match[1]] : []));
}

/** The [package] version of a member, resolving `version.workspace = true`. */
function cargoVersion(member: string): string {
  const path = `${member}/Cargo.toml`;
  const pkg = tomlTable(read(path), "package");
  if (pkg === null) throw new Error(`${path}: no [package]`);
  const own = tomlString(pkg, "version");
  if (own !== null) return own;
  if (/^version\.workspace\s*=\s*true/m.test(pkg)) {
    const shared = tomlTable(rootCargo, "workspace.package");
    const version = shared === null ? null : tomlString(shared, "version");
    if (version !== null) return version;
  }
  throw new Error(`${path}: no version in [package]`);
}

interface ChangelogEntry {
  readonly version: unknown;
  readonly date: unknown;
  readonly items: unknown;
}

function changelog(): ChangelogEntry[] {
  const parsed: unknown = JSON.parse(read("src/changelog.json"));
  if (!Array.isArray(parsed)) throw new Error("changelog.json: not a list");
  return parsed.map((entry: unknown, index) => {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`changelog.json: entry ${String(index)} is not an object`);
    }
    return {
      version: "version" in entry ? entry.version : undefined,
      date: "date" in entry ? entry.date : undefined,
      items: "items" in entry ? entry.items : undefined,
    };
  });
}

const appVersion = jsonVersion("src-tauri/tauri.conf.json");

describe("versions in sync (ADR 0002)", () => {
  it("follows X.Y.Z or X.Y.Z+Build internally", () => {
    expect(appVersion).toMatch(/^\d+\.\d+\.\d+(\+\d+)?$/);
  });

  it("is the same in package.json, tauri.conf.json and every Cargo workspace member", () => {
    expect(jsonVersion("package.json")).toBe(appVersion);
    const members = workspaceMembers();
    expect(members).toContain("src-tauri");
    for (const member of members) {
      expect(cargoVersion(member), member).toBe(appVersion);
    }
  });

  it("is the highest entry in the changelog", () => {
    const versions = changelog().map((entry) => entry.version);
    const highest = versions
      .filter((version): version is string => typeof version === "string")
      .reduce<string | null>(
        (best, version) => (best === null || compareVersions(version, best) > 0 ? version : best),
        null,
      );
    // After a release the files carry X.Y.Z+Build; the changelog names X.Y.Z.
    const base = formatVersion(appVersion).replace(/-\d+$/, "");
    expect(highest).toBe(base);
  });

  it("leaves the changelog entry undated while the files carry no build number", () => {
    // Without +B the files name the upcoming version, which has no release date yet. Only a
    // release writes X.Y.Z+B and dates the entry.
    const base = formatVersion(appVersion).replace(/-\d+$/, "");
    const entry = changelog().find((candidate) => candidate.version === base);
    if (!appVersion.includes("+")) expect(entry?.date, base).toBeNull();
  });
});

describe("changelog", () => {
  const entries = changelog();

  it("names each version once, as plain X.Y.Z", () => {
    const versions = entries.map((entry) => entry.version);
    for (const version of versions) {
      expect(typeof version === "string" && /^\d+\.\d+\.\d+$/.test(version), String(version)).toBe(
        true,
      );
    }
    expect(new Set(versions).size).toBe(versions.length);
  });

  it("leaves only the upcoming, highest version without a date", () => {
    const sorted = [...entries].sort((a, b) =>
      compareVersions(String(b.version), String(a.version)),
    );
    sorted.forEach((entry, index) => {
      if (index === 0) {
        expect(entry.date === null || typeof entry.date === "string").toBe(true);
      } else {
        expect(entry.date, String(entry.version)).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      }
    });
    for (const entry of entries) {
      if (typeof entry.date === "string") {
        expect(Number.isNaN(Date.parse(entry.date)), String(entry.version)).toBe(false);
      }
    }
  });

  it("has every item in all twelve UI languages and no others", () => {
    for (const entry of entries) {
      const label = String(entry.version);
      expect(Array.isArray(entry.items), label).toBe(true);
      const items: unknown[] = Array.isArray(entry.items) ? entry.items : [];
      // Only the undated upcoming entry may still be empty.
      if (entry.date !== null) expect(items.length, label).toBeGreaterThan(0);
      for (const item of items) {
        expect(typeof item === "object" && item !== null, label).toBe(true);
        const texts = typeof item === "object" && item !== null ? item : {};
        expect(Object.keys(texts).sort(), label).toEqual([...LANGUAGES].sort());
        for (const [language, text] of Object.entries(texts)) {
          expect(typeof text === "string" && text.trim().length > 0, `${label} ${language}`).toBe(
            true,
          );
        }
      }
    }
  });

  it("contains neither an en dash nor an em dash", () => {
    expect(read("src/changelog.json")).not.toMatch(
      new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`),
    );
  });
});
