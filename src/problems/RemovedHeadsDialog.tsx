// Changes of a removed device arrived without the removal's confirmation (UX 8.9, security review
// H1): the folder waits. One sentence says what happened; two ways on, both of which take the
// changes in, so both hold back clicks for a second. "Review and undo" is the default: it opens
// the earlier versions at the state before them ("Undo a device", UX 9.4). Escape decides
// nothing and leaves the folder stopped.

import { useId, useState } from "react";

import type { Warning } from "../backend/types";
import { useT, type Translate } from "../i18n";
import type { Open, OpenDialog } from "../main/openDialog";
import { useBackend } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { ArmedButton, Feedback } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";

type HeadsWarning = Extract<Warning, { kind: "removedHeads" }>;

/** The one name to show, when exactly one removed device with a known name sent changes. */
export function onlyDevice(warning: HeadsWarning): string | null {
  const [first, ...rest] = warning.devices;
  return first !== undefined && first !== "" && rest.length === 0 ? first : null;
}

export function headsBody(warning: HeadsWarning, t: Translate): string {
  const device = onlyDevice(warning);
  return device !== null
    ? t("heads.body", { folder: warning.folderName, device })
    : t("heads.bodyMany", {
        folder: warning.folderName,
        count: Math.max(1, warning.devices.length),
      });
}

/** The earlier versions at the state before the changes, labelled with the device if known. */
function restoreBefore(warning: HeadsWarning, entryId: string | null): OpenDialog {
  const device = onlyDevice(warning);
  return {
    kind: "restore",
    folderId: warning.folderId,
    tab: "versions",
    ...(entryId !== null ? { entryId } : {}),
    ...(entryId !== null && device !== null ? { beforeDevice: device } : {}),
  };
}

export function RemovedHeadsDialog({
  warning,
  open,
  onClose,
}: {
  readonly warning: HeadsWarning;
  readonly open: Open;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const bodyId = useId();
  const action = useAction();
  const [accepted, setAccepted] = useState<{ before: string | null } | null>(null);

  const take = (undo: boolean) => {
    void action.run(async () => {
      const result = await backend.acceptRemovedHeads(warning.folderId);
      // "No" in the native question leaves the folder stopped and the question open.
      if (result.kind === "declined") return;
      if (undo) open(restoreBefore(warning, result.beforeEntryId));
      else setAccepted({ before: result.beforeEntryId });
    });
  };

  if (accepted) {
    return (
      <Dialog labelledBy={titleId} onClose={onClose} focusKey="accepted">
        <h2 id={titleId} className="dialog-title">
          {t("heads.title")}
        </h2>
        <Feedback>{t("heads.accepted", { folder: warning.folderName })}</Feedback>
        <div className="dialog-actions">
          <button
            type="button"
            className="button secondary"
            onClick={() => {
              open(restoreBefore(warning, accepted.before));
            }}
          >
            {t("heads.undoLater")}
          </button>
          <button type="button" className="button primary" data-autofocus onClick={onClose}>
            {t("common.close")}
          </button>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      labelledBy={titleId}
      describedBy={bodyId}
      role="alertdialog"
      closeOnOutside={false}
      onClose={onClose}
    >
      <h2 id={titleId} className="dialog-title">
        {t("heads.title")}
      </h2>
      <div id={bodyId} className="dialog-body">
        <p>{headsBody(warning, t)}</p>
        <p className="muted">{t("heads.advice")}</p>
      </div>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <ArmedButton
          armKey={warning.id}
          className="button secondary"
          onClick={() => {
            take(false);
          }}
        >
          {t("heads.accept")}
        </ArmedButton>
        <ArmedButton
          armKey={warning.id}
          autoFocus
          onClick={() => {
            take(true);
          }}
        >
          {t("heads.undo")}
        </ArmedButton>
      </div>
    </Dialog>
  );
}
