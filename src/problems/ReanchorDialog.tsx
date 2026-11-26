// Continuing with the server's state after it showed an older one (UX 8.6): one decision per
// screen. Compare the folder number with another device, then confirm. Without another device,
// continue without comparing, after a sentence that says what that costs. Different numbers end
// the flow. Every confirm button holds back clicks for a second.

import { useId, useState } from "react";

import { useT } from "../i18n";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { ArmedButton, Feedback, Loading, NumberRows } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

type Screen = "compare" | "confirm" | "blind" | "mismatch" | "done";

export function ReanchorDialog({
  folderId,
  folderName,
  onClose,
}: {
  readonly folderId: string;
  readonly folderName: string;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const hasOthers = snapshot.account?.hasOtherDevices ?? false;
  const [screen, setScreen] = useState<Screen>(hasOthers ? "compare" : "blind");
  const titleId = useId();
  const action = useAction();
  const app = t("app.name");

  const go = (compared: boolean) => {
    void action.run(async () => {
      await backend.reanchor(folderId, compared);
      setScreen("done");
    });
  };

  const title = {
    compare: t("older.compare.title"),
    confirm: t("older.confirm.title", { folder: folderName }),
    blind: t("older.blind.title"),
    mismatch: t("older.mismatch.title"),
    done: t("older.done", { folder: folderName }),
  }[screen];

  return (
    <Dialog
      key={screen}
      labelledBy={titleId}
      onClose={onClose}
      closeOnOutside={false}
      role="alertdialog"
    >
      <h2 id={titleId} className="dialog-title">
        {title}
      </h2>
      {screen === "compare" && (
        <CompareScreen
          folderId={folderId}
          folderName={folderName}
          onSame={() => {
            setScreen("confirm");
          }}
          onDifferent={() => {
            setScreen("mismatch");
          }}
          onNoDevice={() => {
            setScreen("blind");
          }}
        />
      )}
      {(screen === "confirm" || screen === "blind") && (
        <>
          <div className="dialog-body">
            {screen === "blind" && <p>{t("older.blind.body", { app })}</p>}
            <p>{t("older.confirm.merge")}</p>
            <p>{t("older.confirm.loss")}</p>
          </div>
          {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
          <div className="dialog-actions">
            <button type="button" className="button secondary" data-autofocus onClick={onClose}>
              {t("common.cancel")}
            </button>
            <ArmedButton
              armKey={screen}
              onClick={() => {
                go(screen === "confirm");
              }}
            >
              {screen === "confirm" ? t("older.confirm.go") : t("older.blind.go")}
            </ArmedButton>
          </div>
        </>
      )}
      {screen === "mismatch" && <MismatchScreen onClose={onClose} />}
      {screen === "done" && (
        <>
          {hasOthers && <p className="dialog-body">{t("older.donePerDevice")}</p>}
          <div className="dialog-actions">
            <button type="button" className="button primary" data-autofocus onClick={onClose}>
              {t("common.close")}
            </button>
          </div>
        </>
      )}
    </Dialog>
  );
}

function CompareScreen({
  folderId,
  folderName,
  onSame,
  onDifferent,
  onNoDevice,
}: {
  readonly folderId: string;
  readonly folderName: string;
  readonly onSame: () => void;
  readonly onDifferent: () => void;
  readonly onNoDevice: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [loaded] = useLoad(() => backend.getFolderNumber(folderId), [backend, folderId]);
  return (
    <>
      <p className="dialog-body">
        {t("older.compare.body", { app: t("app.name"), folder: folderName })}
      </p>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {loaded.status === "ready" &&
        (loaded.data.kind === "offline" ? (
          <Feedback tone="info">{t("folder.number.offline", { app: t("app.name") })}</Feedback>
        ) : (
          <NumberRows rows={loaded.data.number} label={t("folder.menu.number")} />
        ))}
      <div className="dialog-actions">
        <button type="button" className="button secondary" data-autofocus onClick={onDifferent}>
          {t("older.compare.no")}
        </button>
        {loaded.status === "ready" && loaded.data.kind === "number" && (
          <ArmedButton armKey={loaded.data.number.groups.join("")} onClick={onSame}>
            {t("older.compare.yes")}
          </ArmedButton>
        )}
      </div>
      <p className="dialog-foot">
        <button type="button" className="link-button" onClick={onNoDevice}>
          {t("older.noDevice")}
        </button>
      </p>
    </>
  );
}

function MismatchScreen({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const [copied, setCopied] = useState(false);
  return (
    <>
      <p className="dialog-body">{t("older.mismatch.body")}</p>
      {copied && <Feedback>{t("common.reportCopied")}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <button
          type="button"
          className="button secondary"
          onClick={() => {
            void action.run(async () => {
              await backend.copyErrorReport();
              setCopied(true);
            });
          }}
        >
          {t("common.copyReport")}
        </button>
        <button type="button" className="button primary" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </>
  );
}
