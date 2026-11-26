// Contrast of the design tokens (UX 12): text colors need 4.5 : 1 on every surface they sit on,
// in light and dark. Read straight from styles.css, so a token change cannot slip past.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const css = readFileSync(join(import.meta.dirname, "styles.css"), "utf8");

function tokens(selector: string): Map<string, string> {
  const start = css.indexOf(`${selector} {`);
  const block = css.slice(start, css.indexOf("\n}", start));
  const map = new Map<string, string>();
  for (const match of block.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6});/gi)) {
    map.set(match[1] ?? "", match[2] ?? "");
  }
  return map;
}

const dark = tokens(":root");
const light = new Map([...dark, ...tokens(':root[data-theme="light"]')]);

function luminance(hex: string): number {
  const channel = (offset: number) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrast(a: string, b: string): number {
  const one = luminance(a);
  const two = luminance(b);
  return (Math.max(one, two) + 0.05) / (Math.min(one, two) + 0.05);
}

const TEXT = ["text", "muted", "accent", "ok", "warn", "error"];
const SURFACES = ["bg", "panel", "panel-raised"];
const THEMES = [
  ["dark", dark],
  ["light", light],
] as const;

describe("token contrast", () => {
  it("reads the tokens of both themes", () => {
    expect(dark.get("warn")).toBe("#c69026");
    expect(light.get("bg")).toBe("#ffffff");
  });

  for (const [name, theme] of THEMES) {
    it(`keeps text colors at 4.5 : 1 on every surface (${name})`, () => {
      const failures: string[] = [];
      for (const text of TEXT) {
        for (const surface of SURFACES) {
          const ratio = contrast(theme.get(text) ?? "", theme.get(surface) ?? "");
          if (ratio < 4.5) failures.push(`${text} on ${surface}: ${ratio.toFixed(2)}`);
        }
      }
      expect(failures).toEqual([]);
    });

    it(`keeps button labels readable (${name})`, () => {
      expect(
        contrast(theme.get("on-primary") ?? "", theme.get("primary") ?? ""),
      ).toBeGreaterThanOrEqual(4.5);
      expect(
        contrast(theme.get("on-danger") ?? "", theme.get("danger") ?? ""),
      ).toBeGreaterThanOrEqual(4.5);
    });

    it(`gives input outlines 3 : 1 (${name})`, () => {
      expect(
        contrast(theme.get("field-line") ?? theme.get("muted") ?? "", theme.get("bg") ?? ""),
      ).toBeGreaterThanOrEqual(3);
      expect(contrast(theme.get("muted") ?? "", theme.get("panel") ?? "")).toBeGreaterThanOrEqual(
        3,
      );
    });
  }

  it("uses the logo's green as accent and for done, the error red at the same lightness", () => {
    const logo = readFileSync(join(import.meta.dirname, "../src-tauri/app-icon.svg"), "utf8");
    expect(logo).toContain(`fill="${dark.get("accent") ?? ""}"`);
    for (const [, theme] of THEMES) {
      expect(theme.get("ok")).toBe(theme.get("accent"));
      expect(theme.get("primary")).toBe(theme.get("accent"));
      // Same weight, other hue: the two marks differ by less than a quarter in luminance.
      const ok = luminance(theme.get("ok") ?? "");
      const error = luminance(theme.get("error") ?? "");
      expect(Math.abs(ok - error) / Math.max(ok, error)).toBeLessThan(0.25);
    }
  });

  it("tints the tray's attention icon with the window's --error (build.rs)", () => {
    const build = readFileSync(join(import.meta.dirname, "../src-tauri/build.rs"), "utf8");
    expect(build).toContain(
      `("light", "${light.get("text") ?? ""}", "${light.get("error") ?? ""}")`,
    );
    expect(build).toContain(`("dark", "#ffffff", "${dark.get("error") ?? ""}")`);
  });

  it("fixes the light --warn on --panel of the sister app (4.46 : 1)", () => {
    expect(contrast("#9a6700", "#f3f5f8")).toBeLessThan(4.5);
    expect(contrast(light.get("warn") ?? "", light.get("panel") ?? "")).toBeGreaterThanOrEqual(4.5);
  });
});
