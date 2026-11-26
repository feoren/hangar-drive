import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { GLYPHS, iconBody, iconFileName, iconSvg, TRAY_ICONS } from "./icons";

const DIR = join(import.meta.dirname, "icons");

describe("tray icons", () => {
  // `WRITE_ICONS=1 pnpm test` writes the files from icons.ts after a change of the geometry.
  it("are generated from icons.ts", () => {
    for (const icon of TRAY_ICONS) {
      const path = join(DIR, iconFileName(icon));
      if (process.env.WRITE_ICONS === "1") writeFileSync(path, iconSvg(icon));
      expect(readFileSync(path, "utf8"), icon).toBe(iconSvg(icon));
    }
  });

  it("cover the five states plus setup", () => {
    expect([...TRAY_ICONS].sort()).toEqual([
      "attention",
      "offline",
      "paused",
      "setup",
      "syncing",
      "upToDate",
    ]);
  });

  it("each have their own shape, not only their own color", () => {
    const bodies = TRAY_ICONS.map((icon) => iconBody(icon).replace(/(cut|gap)-[a-zA-Z]+/g, "id"));
    expect(new Set(bodies).size).toBe(TRAY_ICONS.length);
    const glyphs = TRAY_ICONS.map((icon) => JSON.stringify(GLYPHS[icon]));
    // The two outline icons have no glyph; the slash tells them apart.
    expect(new Set(glyphs).size).toBe(TRAY_ICONS.length - 1);
    expect(iconBody("offline")).toContain("M5.5 7");
    expect(iconBody("setup")).not.toContain("M5.5 7");
  });

  it("use currentColor so the backend can tint them", () => {
    for (const icon of TRAY_ICONS) {
      expect(iconSvg(icon)).toContain("currentColor");
      expect(iconSvg(icon)).not.toMatch(/#[0-9a-f]{6}/i);
    }
  });

  it("are square SVG files", () => {
    for (const icon of TRAY_ICONS) {
      expect(iconSvg(icon)).toMatch(
        /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="[\d.]+ [\d.]+ 28 28"/,
      );
    }
  });
});
