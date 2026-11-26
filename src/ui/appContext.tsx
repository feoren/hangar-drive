// App-wide state that is not backend data: the chosen language and the tray state with its
// hysteresis, shared so the tray and the status heading never disagree.

import { createContext, useContext, useEffect, useLayoutEffect, useRef, useState } from "react";

import type { BackendEvent, Snapshot } from "../backend/types";
import type { Language } from "../i18n";
import { SyncHysteresis, trayState, type TrayState } from "../tray/trayModel";
import { useBackend } from "./backendContext";

export interface LanguageSetting {
  readonly choice: Language | "system";
  readonly change: (choice: Language | "system") => void;
}

export const LanguageSettingContext = createContext<LanguageSetting>({
  choice: "system",
  change: () => undefined,
});

export function useLanguageSetting(): LanguageSetting {
  return useContext(LanguageSettingContext);
}

export const TrayStateContext = createContext<TrayState>({ kind: "upToDate", waiting: false });

export function useTrayState(): TrayState {
  return useContext(TrayStateContext);
}

/** The tray state for a snapshot, with the 2 s / 3 s hysteresis for "syncing" (UX 6.1). */
export function useComputedTrayState(snapshot: Snapshot): TrayState {
  const [hysteresis] = useState(() => new SyncHysteresis());
  const [tick, setTick] = useState(0);
  const hasWork = snapshot.sync.pendingFiles > 0;
  const [view, setView] = useState(() => ({
    shown: hysteresis.update(hasWork, Date.now()),
    now: Date.now(),
  }));

  useEffect(() => {
    const now = Date.now();
    const shown = hysteresis.update(hasWork, now);
    const wait = hysteresis.pending(now);
    let timer: ReturnType<typeof setTimeout> | null = null;
    if (wait !== null) {
      timer = setTimeout(() => {
        setTick((value) => value + 1);
      }, wait + 10);
    }
    // Timer-driven: the hysteresis decides when the shown value may flip.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setView({ shown, now });
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [hasWork, tick, hysteresis, snapshot]);

  return trayState(snapshot, view.now, view.shown);
}

/** Subscribes to backend events for the lifetime of the component. */
export function useBackendEvent(handler: (event: BackendEvent) => void): void {
  const backend = useBackend();
  const ref = useRef(handler);
  useLayoutEffect(() => {
    ref.current = handler;
  });
  useEffect(
    () =>
      backend.subscribe((event) => {
        ref.current(event);
      }),
    [backend, ref],
  );
}
