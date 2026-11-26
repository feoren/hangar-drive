// The root: loads the first snapshot, keeps it current from the backend's events, applies the
// language, keeps the tray in step and shows either the setup or the main window.

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";

import { loadMockPanel } from "./backend";
import type { Backend, Snapshot } from "./backend/types";
import { createI18n, detectLanguage, I18nContext, useT, type Language } from "./i18n";
import { MainWindow } from "./main/MainWindow";
import { SetupFlow } from "./setup/SetupFlow";
import { parseActionId, trayModel } from "./tray/trayModel";
import {
  LanguageSettingContext,
  TrayStateContext,
  useBackendEvent,
  useComputedTrayState,
} from "./ui/appContext";
import { BackendContext, SnapshotContext, useBackend } from "./ui/backendContext";

// The mock panel exists only next to the mock backend; the production build never loads it.
const MockPanel = loadMockPanel ? lazy(loadMockPanel) : null;

export interface FocusRequest {
  readonly warningId: string | null;
  readonly at: number;
}

/** A link the OS handed over (`openLink`); `at` counts up so the same link twice is two requests. */
export interface IncomingLink {
  readonly link: string;
  readonly at: number;
}

/** A folder whose removed-device question should come to the front (`removedHeads` event). */
export interface HeadsRequest {
  readonly folderId: string;
  readonly at: number;
}

function systemLanguage(): Language {
  return detectLanguage(typeof navigator === "undefined" ? undefined : navigator.language);
}

export function App({ backend }: { readonly backend: Backend }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [choice, setChoice] = useState<Language | "system">("system");
  const [link, setLink] = useState<IncomingLink | null>(null);
  const [heads, setHeads] = useState<HeadsRequest | null>(null);
  const language = choice === "system" ? systemLanguage() : choice;

  useEffect(() => {
    let current = true;
    // The root listens first, so events that arrive before the views exist are kept here.
    const stop = backend.subscribe((event) => {
      if (event.type === "snapshot") setSnapshot(event.snapshot);
      if (event.type === "openLink") {
        setLink((last) => ({ link: event.link, at: (last?.at ?? 0) + 1 }));
        backend.showWindow().catch(() => undefined);
      }
      if (event.type === "removedHeads") {
        setHeads((last) => ({ folderId: event.folderId, at: (last?.at ?? 0) + 1 }));
        backend.showWindow().catch(() => undefined);
      }
    });
    backend.getSnapshot().then(
      (first) => {
        if (current) setSnapshot((existing) => existing ?? first);
      },
      (error: unknown) => {
        console.error("Hangar Drive: first snapshot failed", error);
      },
    );
    backend.getSettings().then(
      (settings) => {
        if (current) setChoice(settings.language);
      },
      () => undefined,
    );
    return () => {
      current = false;
      stop();
    };
  }, [backend]);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  const i18n = useMemo(() => createI18n(language), [language]);
  const languageSetting = useMemo(
    () => ({
      choice,
      change: (next: Language | "system") => {
        setChoice(next);
        backend.setLanguage(next).catch((error: unknown) => {
          console.error("Hangar Drive: saving the language failed", error);
        });
      },
    }),
    [backend, choice],
  );

  return (
    <BackendContext.Provider value={backend}>
      <I18nContext.Provider value={i18n}>
        <LanguageSettingContext.Provider value={languageSetting}>
          {snapshot ? (
            <SnapshotContext.Provider value={snapshot}>
              <Shell snapshot={snapshot} language={language} link={link} heads={heads} />
            </SnapshotContext.Provider>
          ) : (
            <div className="app-loading" aria-busy="true" />
          )}
          {MockPanel && backend.kind === "mock" && (
            <Suspense fallback={null}>
              <MockPanel />
            </Suspense>
          )}
        </LanguageSettingContext.Provider>
      </I18nContext.Provider>
    </BackendContext.Provider>
  );
}

function Shell({
  snapshot,
  language,
  link,
  heads,
}: {
  readonly snapshot: Snapshot;
  readonly language: Language;
  readonly link: IncomingLink | null;
  readonly heads: HeadsRequest | null;
}) {
  const backend = useBackend();
  const state = useComputedTrayState(snapshot);
  const [focus, setFocus] = useState<FocusRequest>({ warningId: null, at: 0 });
  // Keeps the setup on screen for "All set" after the account came into being.
  const [holdSetup, setHoldSetup] = useState(false);
  const t = useT();
  const inSetup = snapshot.setup === "needed" || holdSetup;
  // A link belongs to the view that was on screen when it came: the setup reads it, a set-up
  // window says it is not needed here. Decided once, so finishing the setup does not replay it.
  const [route, setRoute] = useState<{ link: IncomingLink; setup: boolean } | null>(null);
  if (link && link.at !== route?.link.at) setRoute({ link, setup: inSetup });

  // The tray shows what the window computed (UX 6.1, 6.2).
  useEffect(() => {
    backend.updateTray(trayModel(snapshot, state, t, language, Date.now())).catch(() => undefined);
  }, [backend, snapshot, state, t, language]);

  const showProblem = useCallback(
    (warningId: string | null) => {
      setFocus({ warningId, at: Date.now() });
      backend.showWindow().catch(() => undefined);
    },
    [backend],
  );

  useBackendEvent((event) => {
    if (event.type === "focusWarning") showProblem(event.warningId);
    if (event.type !== "trayAction") return;
    const action = parseActionId(event.actionId);
    if (!action) return;
    const done = (promise: Promise<void>) => {
      promise.catch((error: unknown) => {
        console.error("Hangar Drive: tray action failed", error);
      });
    };
    switch (action.kind) {
      case "showProblem":
        showProblem(null);
        break;
      case "openFolder":
        done(backend.openFolder(action.folderId));
        break;
      case "openApp":
        done(backend.showWindow());
        break;
      case "pause":
        done(backend.pause(action.duration));
        break;
      case "resume":
        done(backend.resume());
        break;
      case "quit":
        done(backend.quit());
        break;
    }
  });

  return (
    <TrayStateContext.Provider value={state}>
      {inSetup ? (
        <SetupFlow
          link={route?.setup ? route.link : null}
          onHold={setHoldSetup}
          onFinished={() => {
            setHoldSetup(false);
          }}
        />
      ) : (
        <MainWindow focus={focus} link={route && !route.setup ? route.link : null} heads={heads} />
      )}
    </TrayStateContext.Provider>
  );
}
