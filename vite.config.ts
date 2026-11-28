/// <reference types="node" />
import react from "@vitejs/plugin-react";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { configDefaults, defineConfig } from "vitest/config";

// Build number = buildNumberBase from package.json + number of commits (the same scheme as
// Hangar). Without Git or without a commit there is no build number instead of an error.
function buildNumber(): number | null {
  try {
    const pkg: unknown = JSON.parse(readFileSync("package.json", "utf8"));
    const base =
      typeof pkg === "object" && pkg !== null && "buildNumberBase" in pkg
        ? Number(pkg.buildNumberBase)
        : 0;
    const count = Number(
      // stderr ignored: before the first commit Git complains about HEAD, which is no error here.
      execFileSync("git", ["rev-list", "--count", "HEAD"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim(),
    );
    return Number.isInteger(count) && count > 0 && Number.isInteger(base) && base >= 0
      ? base + count
      : null;
  } catch {
    return null;
  }
}

/** The Vite mode of the app's own build (`pnpm build:app`, tauri.conf.json `beforeBuildCommand`). */
export const APP_MODE = "app";

/**
 * Which backend the window uses (src/backend/index.ts): "tauri", "mock" or "auto" (default:
 * Tauri inside the app, the mock in a plain browser). The app's build always takes "tauri", so
 * neither the mock nor its dev panel ships in the bundle, whatever the environment says (supply
 * chain review INFO 1); `pnpm build` for a browser preview keeps the mock.
 */
export function backendFor(mode: string, env: string | undefined): string {
  return mode === APP_MODE ? "tauri" : (env ?? "auto");
}

// The app's version from package.json (kept equal to tauri.conf.json and Cargo.toml by the
// release script), so the window shows it without asking the backend first.
function appVersion(): string | null {
  try {
    const pkg: unknown = JSON.parse(readFileSync("package.json", "utf8"));
    return typeof pkg === "object" &&
      pkg !== null &&
      "version" in pkg &&
      typeof pkg.version === "string"
      ? pkg.version
      : null;
  } catch {
    return null;
  }
}

// Fixed values that Tauri expects (devUrl in src-tauri/tauri.conf.json).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: {
    __HANGAR_DRIVE_BUILD__: JSON.stringify(buildNumber()),
    __HANGAR_DRIVE_VERSION__: JSON.stringify(appVersion()),
    __HANGAR_DRIVE_BACKEND__: JSON.stringify(backendFor(mode, process.env.HANGAR_DRIVE_BACKEND)),
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    // .claude/worktrees holds agents' working copies; they do not belong in this dev server.
    watch: { ignored: ["**/src-tauri/**", "**/target/**", "**/.claude/**"] },
  },
  build: {
    target: "es2022",
  },
  test: {
    exclude: [...configDefaults.exclude, "**/.claude/**", "target/**", "output/**", "release/**"],
  },
}));
