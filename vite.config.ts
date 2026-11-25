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

// Fixed values that Tauri expects (devUrl in src-tauri/tauri.conf.json).
export default defineConfig({
  plugins: [react()],
  define: { __HANGAR_DRIVE_BUILD__: JSON.stringify(buildNumber()) },
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
});
