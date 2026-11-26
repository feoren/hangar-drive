// "What now?" after a suspected attack (UX 9.4): three numbered steps, because the order matters.
// Removing the device comes first; restoring before that would be undone by the infected device.

import { useId, useState } from "react";

import type { Warning } from "../backend/types";
import { useT, type Translate } from "../i18n";
import type { Open } from "../main/openDialog";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";

type Suspect = Extract<Warning, { kind: "suspect" }>;

/**
 * The banner and notification title: the device that wrote the burst, or the folder while this
 * device cannot tell which device it was (the folder is not synced here, or its newest changes
 * have not arrived yet).
 */
export function suspectTitle(warning: Suspect, t: Translate): string {
  return warning.deviceName === ""
    ? t("suspect.titleFolder", { folder: warning.folderName })
    : t("suspect.title", { device: warning.deviceName });
}

export function SuspectDialog({
  warning,
  open,
  onClose,
}: {
  readonly warning: Suspect;
  readonly open: Open;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const snapshot = useSnapshot();
  // The timeline needs the folder on this device; elsewhere the step names where to do it.
  const local = snapshot.folders.some((folder) => folder.id === warning.folderId);
  const known = warning.deviceId !== "";
  const titleId = useId();
  const action = useAction();
  const [removed, setRemoved] = useState(false);

  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("suspect.what")}
      </h2>
      <ol className="steps">
        <li className={removed ? "step done" : "step"}>
          <p>
            {known ? t("suspect.step1", { device: warning.deviceName }) : t("suspect.step1Unknown")}
          </p>
          {removed ? (
            <Feedback>{t("devices.removed", { device: warning.deviceName })}</Feedback>
          ) : !known ? (
            <button
              type="button"
              className="button secondary small"
              data-autofocus
              onClick={() => {
                open({ kind: "devices" });
              }}
            >
              {t("suspect.devices")}
            </button>
          ) : (
            <button
              type="button"
              className="button secondary small"
              data-autofocus
              disabled={action.pending}
              onClick={() => {
                // The shell asks natively with the device's name (security review M4).
                void action.run(async () => {
                  const outcome = await backend.removeDevice(warning.deviceId);
                  if (outcome === "confirmed") setRemoved(true);
                });
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
          <p>
            {local
              ? t("suspect.step3")
              : t("suspect.step3Elsewhere", { folder: warning.folderName })}
          </p>
          {local && (
            <button
              type="button"
              className={removed ? "button primary small" : "button secondary small"}
              onClick={() => {
                open({
                  kind: "restore",
                  folderId: warning.folderId,
                  tab: "versions",
                  entryId: warning.entryId,
                  // Without a device the entry keeps its plain label.
                  ...(known ? { beforeDevice: warning.deviceName } : {}),
                });
              }}
            >
              {t("suspect.view")}
            </button>
          )}
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
