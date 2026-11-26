// Loading data and running actions with visible feedback. Every failure ends in a sentence the
// person can act on (errorText), never in a silent console message.

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

import { errorCode } from "../backend/errors";
import type { MessageKey, Translate } from "../i18n";

/** The general sentence for an unexpected failure. */
export function errorKey(error: unknown): MessageKey {
  switch (errorCode(error)) {
    case "notImplemented":
      return "error.notReady";
    case "busy":
      return "error.busy";
    case "locked":
      return "error.lockedFile";
    default:
      return "error.unexpected";
  }
}

export function errorText(error: unknown, t: Translate): string {
  return t(errorKey(error), { app: t("app.name") });
}

export type Loaded<T> =
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly data: T }
  | { readonly status: "failed"; readonly error: unknown };

/** Loads once per change of `deps`; `reload` loads again. Stale answers are dropped. */
export function useLoad<T>(
  load: () => Promise<T>,
  deps: readonly unknown[],
): [Loaded<T>, () => void] {
  const [round, setRound] = useState(0);
  const key = [...deps, round];
  const [state, setState] = useState<{ key: readonly unknown[]; loaded: Loaded<T> } | null>(null);
  const loadRef = useRef(load);
  useLayoutEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    let current = true;
    const started = [...deps, round];
    loadRef.current().then(
      (data) => {
        if (current) setState({ key: started, loaded: { status: "ready", data } });
      },
      (error: unknown) => {
        if (current) setState({ key: started, loaded: { status: "failed", error } });
      },
    );
    return () => {
      current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the caller names the dependencies
  }, key);

  const reload = useCallback(() => {
    setRound((value) => value + 1);
  }, []);
  // A reload keeps showing the old data until the new answer is there; new deps show loading.
  const sameDeps = state !== null && sameValues(state.key.slice(0, -1), deps);
  const loaded: Loaded<T> = state === null || !sameDeps ? { status: "loading" } : state.loaded;
  return [loaded, reload];
}

function sameValues(a: readonly unknown[], b: readonly unknown[]): boolean {
  return a.length === b.length && a.every((value, index) => Object.is(value, b[index]));
}

export interface Action {
  readonly pending: boolean;
  /** Runs `task`; while it runs, further calls are ignored. Failures land in `error`. */
  run: <T>(task: () => Promise<T>) => Promise<T | undefined>;
  readonly error: unknown;
  clearError: () => void;
}

export function useAction(): Action {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const busy = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async <T>(task: () => Promise<T>): Promise<T | undefined> => {
    if (busy.current) return undefined;
    busy.current = true;
    setPending(true);
    setError(null);
    try {
      return await task();
    } catch (caught) {
      if (mounted.current) setError(caught);
      return undefined;
    } finally {
      busy.current = false;
      if (mounted.current) setPending(false);
    }
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return { pending, run, error, clearError };
}
