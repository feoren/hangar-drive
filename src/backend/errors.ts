// Unexpected failures of a backend call. Expected outcomes are part of the return types instead
// (types.ts); these are the cases the window can only report in general words.

export type BackendErrorCode =
  /** The backend has no command of that name yet (the Tauri side is still being built). */
  | "notImplemented"
  /** The backend is busy with another action of the same kind. */
  | "busy"
  /** A file is open in another program. */
  | "locked"
  /** The backend answered with data the window could not read. */
  | "badResponse"
  /**
   * This build has no updater key yet, so it cannot update itself. Not shown as an error: the
   * window hides "Update now" instead.
   */
  | "updatesOff"
  | "unexpected";

export class BackendError extends Error {
  readonly code: BackendErrorCode;
  /** The command that failed, for the error report; never shown in the main text. */
  readonly command: string;

  constructor(code: BackendErrorCode, command: string, detail?: string) {
    super(detail ? `${command}: ${code} (${detail})` : `${command}: ${code}`);
    this.name = "BackendError";
    this.code = code;
    this.command = command;
  }
}

export function errorCode(error: unknown): BackendErrorCode {
  return error instanceof BackendError ? error.code : "unexpected";
}
