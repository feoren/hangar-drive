// The backend and its latest snapshot for every view. Views call backend methods through
// `useBackend()` and read the state through `useSnapshot()`; nothing else holds app state.

import { createContext, useContext, useEffect, useState } from "react";

import type { Backend, Snapshot } from "../backend/types";

export const BackendContext = createContext<Backend | null>(null);
export const SnapshotContext = createContext<Snapshot | null>(null);

export function useBackend(): Backend {
  const backend = useContext(BackendContext);
  if (!backend) throw new Error("useBackend outside of BackendContext");
  return backend;
}

export function useSnapshot(): Snapshot {
  const snapshot = useContext(SnapshotContext);
  if (!snapshot) throw new Error("useSnapshot before the first snapshot");
  return snapshot;
}

/** Current time, refreshed every `everyMs`, for relative times ("2 min ago"). */
export function useNow(everyMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
    }, everyMs);
    return () => {
      clearInterval(timer);
    };
  }, [everyMs]);
  return now;
}
