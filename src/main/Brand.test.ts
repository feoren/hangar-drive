import { describe, expect, it } from "vitest";

import { brandVersion } from "./Brand";

describe("brandVersion", () => {
  it("adds the build number and the beta badge below 1.0.0", () => {
    expect(brandVersion("0.1.0", 33)).toEqual({ number: "0.1.0-33", beta: true });
  });

  it("drops the badge from 1.0.0 on and keeps a version without a build", () => {
    expect(brandVersion("1.2.0", null)).toEqual({ number: "1.2.0", beta: false });
  });

  it("shows nothing without a version", () => {
    expect(brandVersion(null, 33)).toBeNull();
  });
});
