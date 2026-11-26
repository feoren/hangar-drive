import { describe, expect, it } from "vitest";

import { cleanName, nameProblem, strictNameProblem } from "./names";

const FILLER = String.fromCharCode(0x3164);

describe("device names (rule N5)", () => {
  it("trims whitespace at the edges before sending", () => {
    expect(cleanName(" Laptop ")).toBe("Laptop");
    expect(nameProblem(" Laptop ")).toBeNull();
  });

  it("refuses names that are empty or only filler characters", () => {
    expect(nameProblem("")).toBe("blank");
    expect(nameProblem("   ")).toBe("blank");
    expect(nameProblem(FILLER)).toBe("blank");
    for (const code of [0x3164, 0x115f, 0x1160, 0xffa0]) {
      expect(nameProblem(` ${String.fromCharCode(code)} `), code.toString(16)).toBe("blank");
    }
    expect(nameProblem(`${FILLER}Laptop`)).toBeNull();
  });

  it("checks what the backend receives the way the backend does", () => {
    expect(strictNameProblem(" Laptop ")).toBe("edgeWhitespace");
    expect(strictNameProblem(FILLER)).toBe("blank");
    expect(strictNameProblem("Laptop")).toBeNull();
  });
});
