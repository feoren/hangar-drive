// The traffic readings outside React state, like the system bar of the sister app: one store per
// backend, listening only while the traffic line is mounted. Every reading renders the line and
// nothing else of the window (useSyncExternalStore in TrafficBar.tsx). A reading after a gap,
// and the first subscriber, fetch the last minute from the backend instead.

import { useSyncExternalStore } from "react";

import type { Backend, TrafficSample, Unsubscribe } from "../backend/types";
import { advance, EMPTY_TRAFFIC, fromHistory, type TrafficState } from "./traffic";

export interface TrafficStore {
  readonly subscribe: (listener: () => void) => () => void;
  readonly get: () => TrafficState;
}

export function createTrafficStore(backend: Backend): TrafficStore {
  let state: TrafficState = EMPTY_TRAFFIC;
  const listeners = new Set<() => void>();
  let stop: Unsubscribe | null = null;
  let fetching = false;

  const publish = (next: TrafficState) => {
    state = next;
    for (const listener of listeners) listener();
  };

  const resync = () => {
    if (fetching) return;
    fetching = true;
    backend.getTraffic().then(
      (history) => {
        fetching = false;
        // Unmounted meanwhile, or a reading came through after the answer was made.
        if (listeners.size === 0 || history.tick < state.tick) return;
        publish(fromHistory(history));
      },
      () => {
        fetching = false;
      },
    );
  };

  const onSample = (sample: TrafficSample) => {
    const next = advance(state, sample);
    if (next === null) resync();
    else publish(next);
  };

  return {
    subscribe(listener) {
      listeners.add(listener);
      if (listeners.size === 1) {
        stop = backend.subscribeTraffic(onSample);
        resync();
      }
      return () => {
        listeners.delete(listener);
        if (listeners.size > 0) return;
        stop?.();
        stop = null;
        state = EMPTY_TRAFFIC;
      };
    },
    get: () => state,
  };
}

const stores = new WeakMap<Backend, TrafficStore>();

/** The one store of `backend`. */
export function trafficStore(backend: Backend): TrafficStore {
  let store = stores.get(backend);
  if (!store) {
    store = createTrafficStore(backend);
    stores.set(backend, store);
  }
  return store;
}

/** The traffic of the last minute; renders the calling component for every reading. */
export function useTraffic(backend: Backend): TrafficState {
  const store = trafficStore(backend);
  return useSyncExternalStore(store.subscribe, store.get);
}
