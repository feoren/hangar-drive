// Which backend the window talks to. The build constant `__HANGAR_DRIVE_BACKEND__` (vite.config.ts,
// environment variable HANGAR_DRIVE_BACKEND) decides: "tauri", "mock" or "auto". "auto" uses the
// Tauri bridge inside the app and the mock everywhere else, so `pnpm dev` in a browser runs on the
// mock without any setup. With "tauri" the mock and its dev panel are not part of the bundle.

import type { Backend } from "./types";

declare const __HANGAR_DRIVE_BACKEND__: string | undefined;

export type BackendChoice = "tauri" | "mock" | "auto";

const CHOICE = typeof __HANGAR_DRIVE_BACKEND__ === "string" ? __HANGAR_DRIVE_BACKEND__ : "auto";

export function backendChoice(): BackendChoice {
  return CHOICE === "tauri" || CHOICE === "mock" ? CHOICE : "auto";
}

/** False in a Tauri-only build; the bundler then drops every import of the mock. */
export const MOCK_ALLOWED: boolean = CHOICE !== "tauri";

/** True inside the Tauri webview (its IPC bridge is on `window`). */
export function insideTauri(scope: object = globalThis): boolean {
  return "__TAURI_INTERNALS__" in scope;
}

export async function createBackend(search = ""): Promise<Backend> {
  if (!MOCK_ALLOWED || (CHOICE !== "mock" && insideTauri())) {
    const { TauriBackend } = await import("./tauri/tauriBackend");
    return new TauriBackend();
  }
  const { createDevMock } = await import("./mock/devMock");
  return createDevMock(search);
}

/** Loads the dev panel of the mock; null in a Tauri-only build (the panel is not bundled). */
export const loadMockPanel: (() => Promise<typeof import("../dev/MockPanel")>) | null = MOCK_ALLOWED
  ? () => import("../dev/MockPanel")
  : null;
