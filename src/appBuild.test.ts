/// <reference types="node" />
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import viteConfig, { APP_MODE, backendFor } from "../vite.config";

// Supply chain review INFO 1: the app's bundle never carries the mock backend or its dev panel.
// The Tauri build runs `pnpm build:app`, whose Vite mode fixes the backend to "tauri" (then
// src/backend/index.ts imports neither), whatever HANGAR_DRIVE_BACKEND says; the plain
// `pnpm build` for a browser preview keeps "auto".

function json(path: string): unknown {
  return JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), "utf8"));
}

function field(value: unknown, ...keys: string[]): unknown {
  let current = value;
  for (const key of keys) {
    if (typeof current !== "object" || current === null || !(key in current)) return undefined;
    current = Reflect.get(current, key);
  }
  return current;
}

describe("the app's build", () => {
  it("is the one Tauri runs, in the app mode", () => {
    expect(field(json("src-tauri/tauri.conf.json"), "build", "beforeBuildCommand")).toBe(
      "pnpm build:app",
    );
    const scripts = field(json("package.json"), "scripts");
    expect(field(scripts, "build:app")).toBe(`tsc --noEmit && vite build --mode ${APP_MODE}`);
    expect(field(scripts, "build")).toBe("tsc --noEmit && vite build");
  });

  it("takes the Tauri backend whatever the environment says", () => {
    for (const env of [undefined, "auto", "mock", "tauri"]) {
      expect(backendFor(APP_MODE, env)).toBe("tauri");
    }
    expect(backendFor("production", undefined)).toBe("auto");
    expect(backendFor("production", "mock")).toBe("mock");
    expect(backendFor("development", undefined)).toBe("auto");
  });

  it("puts that choice into the bundle's constant", () => {
    const resolved = viteConfig({ mode: APP_MODE, command: "build" });
    expect(field(resolved, "define", "__HANGAR_DRIVE_BACKEND__")).toBe('"tauri"');
    const preview = viteConfig({ mode: "production", command: "build" });
    expect(field(preview, "define", "__HANGAR_DRIVE_BACKEND__")).toBe(
      JSON.stringify(process.env.HANGAR_DRIVE_BACKEND ?? "auto"),
    );
  });
});
