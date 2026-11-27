import { describe, expect, it } from "vitest";

import { GLYPHS, iconBody, TRAY_ICONS, VIEW_BOX } from "./icons";

describe("status shapes", () => {
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

  it("use currentColor so the window's color tokens tint them", () => {
    for (const icon of TRAY_ICONS) {
      expect(iconBody(icon)).toContain("currentColor");
      expect(iconBody(icon)).not.toMatch(/#[0-9a-f]{6}/i);
    }
  });

  it("sit in a square view box", () => {
    expect(VIEW_BOX).toMatch(/^[\d.]+ [\d.]+ 28 28$/);
  });
});
