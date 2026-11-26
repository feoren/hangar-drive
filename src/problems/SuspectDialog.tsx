// "What now?" after a suspected attack (UX 9.4): three numbered steps, because the order matters.
// Removing the device comes first; restoring before that would be undone by the infected device.

import { useId, useState } from "react";

import type { Warning } from "../backend/types";
import { useT } from "../i18n";
import type { Open } from "../main/openDialog";
import { useBackend } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";

export function SuspectDialog({
  warning,
  open,
  onClose,
}: {
  readonly warning: Extract<Warning, { kind: "suspect" }>;
  readonly open: Open;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const action = useAction();
  const [asking, setAsking] = useState(false);
  const [removed, setRemoved] = useState(false);
  const app = t("app.name");

  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("suspect.what")}
      </h2>
      <ol className="steps">
        <li className={removed ? "step done" : "step"}>
          <p>{t("suspect.step1", { device: warning.deviceName })}</p>
          {removed ? (
            <Feedback>{t("devices.removed", { device: warning.deviceName })}</Feedback>
          ) : asking ? (
            <div
              className="inline-confirm"
              role="group"
              aria-label={t("devices.remove.title", { device: warning.deviceName })}
            >
              <p className="inline-confirm-title">
                {t("devices.remove.title", { device: warning.deviceName })}
              </p>
              <p className="muted">{t("devices.remove.body", { app })}</p>
              <div className="group-actions">
                <button
                  type="button"
                  className="button secondary small"
                  autoFocus
                  onClick={() => {
                    setAsking(false);
                  }}
                >
                  {t("common.cancel")}
                </button>
                <button
                  type="button"
                  className="button danger small"
                  disabled={action.pending}
                  onClick={() => {
                    void action.run(async () => {
                      await backend.removeDevice(warning.deviceId);
                      setRemoved(true);
                      setAsking(false);
                    });
                  }}
                >
                  {t("devices.remove")}
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              className="button secondary small"
              data-autofocus
              onClick={() => {
                setAsking(true);
              }}
            >
              {t("devices.remove")}
            </button>
          )}
        </li>
        <li className="step">
          <p>{t("suspect.step2")}</p>
        </li>
        <li className="step">
          <p>{t("suspect.step3")}</p>
          <button
            type="button"
            className={removed ? "button primary small" : "button secondary small"}
            onClick={() => {
              open({
                kind: "restore",
                folderId: warning.folderId,
                tab: "versions",
                entryId: warning.entryId,
                beforeDevice: warning.deviceName,
              });
            }}
          >
            {t("suspect.view")}
          </button>
        </li>
      </ol>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

/** "That was not me" after this device was removed (UX 8.8). */
export function NotMeDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const titleId = useId();
  return (
    <Dialog labelledBy={titleId} onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("removed.notMe")}
      </h2>
      <p className="dialog-body">{t("removed.notMeBody", { app: t("app.name") })}</p>
      <div className="dialog-actions">
        <button type="button" className="button primary" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}
