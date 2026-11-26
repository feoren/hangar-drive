// First start (UX 4): three doors, because there are exactly three situations. A new account, an
// additional device, or the recovery sheet when no device is left.

import { useState } from "react";

import { useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { Feedback } from "../ui/parts";
import { StatusMark } from "../ui/StatusMark";
import { errorText, useAction } from "../ui/useAsync";
import { NewAccountFlow } from "./NewAccountFlow";
import { PairFlow } from "./PairFlow";
import { RecoverFlow } from "./RecoverFlow";

type Door = "welcome" | "new" | "pair" | "recover" | "ready";

export function SetupFlow({
  onHold,
  onFinished,
}: {
  /** Keeps the setup on screen after the account exists, for the "All set" screen. */
  readonly onHold: (hold: boolean) => void;
  readonly onFinished: () => void;
}) {
  const backend = useBackend();
  const [door, setDoor] = useState<Door>("welcome");
  const welcome = () => {
    setDoor("welcome");
  };

  return (
    <div className="setup">
      <main className="setup-page" key={door}>
        {door === "welcome" && <Welcome onChoose={setDoor} />}
        {door === "new" && (
          <NewAccountFlow
            onBack={welcome}
            onFinish={async (path) => {
              onHold(true);
              try {
                await backend.finishSetup(path);
                setDoor("ready");
              } catch (error) {
                onHold(false);
                throw error;
              }
            }}
          />
        )}
        {door === "pair" && <PairFlow onBack={welcome} onDone={onFinished} />}
        {door === "recover" && <RecoverFlow onBack={welcome} onDone={onFinished} />}
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
