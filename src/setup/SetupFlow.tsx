// First start (UX 4): three doors, because there are exactly three situations. A new account, an
// additional device, or the recovery sheet when no device is left. A link from the OS or a link of
// another kind pasted into a field opens the door it belongs to, with the link filled in.

import { useRef, useState } from "react";

import type { IncomingLink } from "../App";
import type { LinkKind } from "../backend/types";
import { cleanLink, linkKind } from "../domain/links";

import { useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { noOverlay, useFocusKeeper } from "../ui/focusKeeper";
import { Feedback } from "../ui/parts";
import { StatusMark } from "../ui/StatusMark";
import { errorText, useAction } from "../ui/useAsync";
import { NewAccountFlow } from "./NewAccountFlow";
import { PairFlow } from "./PairFlow";
import { RecoverFlow } from "./RecoverFlow";

type Door = "welcome" | "new" | "pair" | "recover" | "ready";

const DOOR: Record<LinkKind, Door> = { invite: "new", pair: "pair", recover: "recover" };

export function SetupFlow({
  link,
  onHold,
  onFinished,
}: {
  /** The last link the OS handed over while the setup was on screen. */
  readonly link: IncomingLink | null;
  /** Keeps the setup on screen after the account exists, for the "All set" screen. */
  readonly onHold: (hold: boolean) => void;
  readonly onFinished: () => void;
}) {
  const backend = useBackend();
  const page = useRef<HTMLDivElement>(null);
  // A new step takes the focus: its marked control, else its title, so a keyboard or screen
  // reader user starts where the step starts instead of at the top of the page (UX 12).
  useFocusKeeper(page, {
    near: false,
    inFront: noOverlay,
    fallback: (root) =>
      root.querySelector<HTMLElement>("[data-autofocus]") ??
      root.querySelector<HTMLElement>("h1[tabindex]"),
  });
  const [door, setDoor] = useState<Door>("welcome");
  // The link a door starts with, and a counter so a new link opens the door afresh.
  const [start, setStart] = useState<{ link: string; round: number }>({ link: "", round: 0 });
  const [handled, setHandled] = useState(0);
  const go = (kind: LinkKind, text: string) => {
    setDoor(DOOR[kind]);
    setStart((last) => ({ link: cleanLink(text), round: last.round + 1 }));
  };
  if (link && link.at !== handled) {
    setHandled(link.at);
    const kind = linkKind(link.link);
    if (kind && door !== "ready") go(kind, link.link);
  }
  const welcome = () => {
    setDoor("welcome");
    setStart((last) => ({ link: "", round: last.round + 1 }));
  };

  return (
    <div ref={page} className="setup">
      <main className="setup-page" key={`${door}-${String(start.round)}`}>
        {door === "welcome" && <Welcome onChoose={setDoor} />}
        {door === "new" && (
          <NewAccountFlow
            initialLink={start.link}
            onSwitch={go}
            onBack={welcome}
            onFinish={async (token) => {
              onHold(true);
              try {
                await backend.finishSetup(token);
                setDoor("ready");
              } catch (error) {
                onHold(false);
                throw error;
              }
            }}
          />
        )}
        {door === "pair" && (
          <PairFlow initialLink={start.link} onSwitch={go} onBack={welcome} onDone={onFinished} />
        )}
        {door === "recover" && (
          <RecoverFlow
            initialLink={start.link}
            onSwitch={go}
            onBack={welcome}
            onDone={onFinished}
          />
        )}
        {door === "ready" && <Ready onDone={onFinished} />}
      </main>
    </div>
  );
}

function Welcome({ onChoose }: { readonly onChoose: (door: Door) => void }) {
  const t = useT();
  const app = t("app.name");
  return (
    <div className="welcome">
      <StatusMark icon="upToDate" size={72} className="welcome-mark" />
      <h1 className="welcome-title">{t("welcome.title", { app })}</h1>
      <p className="welcome-body">{t("welcome.body")}</p>
      <div className="welcome-doors">
        <button
          type="button"
          className="button primary large"
          autoFocus
          onClick={() => {
            onChoose("new");
          }}
        >
          {t("welcome.invite")}
        </button>
        <button
          type="button"
          className="button secondary large"
          onClick={() => {
            onChoose("pair");
          }}
        >
          {t("welcome.pair", { app })}
        </button>
      </div>
      <button
        type="button"
        className="link-button welcome-recover"
        onClick={() => {
          onChoose("recover");
        }}
      >
        {t("welcome.recover")}
      </button>
    </div>
  );
}

function Ready({ onDone }: { readonly onDone: () => void }) {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const app = t("app.name");
  return (
    <div className="welcome ready">
      <StatusMark icon="upToDate" size={72} className="welcome-mark tone-ok" />
      <h1 className="welcome-title" tabIndex={-1}>
        {t("setup.ready.title")}
      </h1>
      <p className="welcome-body">{t("setup.ready.body", { app })}</p>
      <div className="welcome-doors">
        <button
          type="button"
          className="button primary large"
          autoFocus
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              await backend.openFolder(null);
              onDone();
            });
          }}
        >
          {t("setup.ready.open")}
        </button>
        <button type="button" className="button secondary large" onClick={onDone}>
          {t("setup.ready.continue")}
        </button>
      </div>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <p className="tray-hint">{t("setup.ready.trayHint", { app })}</p>
    </div>
  );
}
