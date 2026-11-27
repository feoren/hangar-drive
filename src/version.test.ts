import { describe, expect, it } from "vitest";

import { compareVersions, formatVersion, parseVersion, versionParts, withBuild } from "./version";

describe("version scheme (ADR 0002)", () => {
  it("reads the internal, the displayed and the plain form", () => {
    expect(parseVersion("0.12.224+1548")).toEqual({
      major: 0,
      minor: 12,
      revision: 224,
      build: 1548,
    });
    expect(parseVersion("0.12.224-1548")?.build).toBe(1548);
    expect(parseVersion("v1.2.3")).toEqual({ major: 1, minor: 2, revision: 3, build: null });
    expect(parseVersion("1.2")).toBeNull();
    expect(parseVersion("1.2.3-beta")).toBeNull();
  });

  it("displays the build number after a dash, never after a plus", () => {
    expect(formatVersion("0.1.0+12")).toBe("0.1.0-12");
    expect(formatVersion("0.1.0")).toBe("0.1.0");
    expect(formatVersion("unknown")).toBe("unknown");
  });

  it("adds the build number of a development build only when the version has none", () => {
    expect(withBuild("0.1.0", 12)).toBe("0.1.0+12");
    expect(withBuild("0.1.0+12", 99)).toBe("0.1.0+12");
    expect(withBuild("0.1.0", null)).toBe("0.1.0");
  });

  it("compares by X.Y.Z with multi-digit parts, ignoring the build number", () => {
    expect(compareVersions("0.10.0", "0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
    expect(compareVersions("0.1.1", "0.1.0+500")).toBeGreaterThan(0);
    expect(compareVersions("0.1.0+1", "0.1.0+2")).toBe(0);
    expect(compareVersions("broken", "0.0.0")).toBeLessThan(0);
  });
});

describe("versionParts", () => {
  it("marks every 0.x version as beta, like Hangar", () => {
    expect(versionParts("0.1.0+12")).toEqual({ number: "0.1.0-12", beta: true });
    expect(versionParts("0.16.0")).toEqual({ number: "0.16.0", beta: true });
  });

  it("drops the badge from 1.0.0 on and for unreadable input", () => {
    expect(versionParts("1.0.0-3")).toEqual({ number: "1.0.0-3", beta: false });
    expect(versionParts("dev")).toEqual({ number: "dev", beta: false });
  });
});
