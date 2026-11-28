// Injected by vite.config.ts at build time (`define`). If the value is missing (tests, builds
// without Git or before the first commit), there is simply no build number instead of an error.
declare const __HANGAR_DRIVE_BUILD__: number | null | undefined;

export const HANGAR_DRIVE_BUILD: number | null =
  typeof __HANGAR_DRIVE_BUILD__ === "number" ? __HANGAR_DRIVE_BUILD__ : null;

// The app's version (package.json), injected the same way. The window and the backend ship in one
// binary, so this is the version the backend reports too; `null` only outside a Vite build.
declare const __HANGAR_DRIVE_VERSION__: string | null | undefined;

export const HANGAR_DRIVE_VERSION: string | null =
  typeof __HANGAR_DRIVE_VERSION__ === "string" ? __HANGAR_DRIVE_VERSION__ : null;
