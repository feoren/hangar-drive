// Many deletions at once (UX 8.1), in two variants of one dialog: deletions on this device that
// wait before they go to the other devices ("massDelete"), and deletions another device made that
// wait before they happen here ("incomingDelete", ADR 0001 amendment "incoming mass deletes").
// Only the deletions wait. "Restore" has the focus because it loses nothing; "Yes, delete" is
// the danger style and asks once more natively. Escape closes without deciding.

import { useId, useState } from "react";

import type { MassDeleteOutcome, Warning } from "../backend/types";
import { formatDate } from "../format";
import { displayName, useLanguage, useT, type Language, type Translate } from "../i18n";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

export type DeleteWarning = Extract<Warning, { kind: "massDelete" | "incomingDelete" }>;

/** The heading of a delete question, also the banner's title. */
export function deleteTitle(warning: DeleteWarning, t: Translate): string {
  if (warning.kind === "massDelete") return t("deletes.title", { count: warning.count });
  const folder = warning.folderName;
  return warning.device === null
    ? t("incoming.titleUnknown", { count: warning.count, folder })
    : t("incoming.title", { count: warning.count, folder, device: warning.device });
}

/**
 * The quiet line under the heading that names when the deleting device joined the account, from
 * the verified device log (security review L5): any device can take another one's name, not
 * this date, and it is the date the device list shows. Null without a known device.
 */
export function deviceLine(
  warning: DeleteWarning,
  t: Translate,
  language: Language,
  now: number,
): string | null {
  if (warning.kind !== "incomingDelete" || warning.device === null) return null;
  if (warning.deviceAdded === null) return null;
  return t("incoming.deviceSince", {
    device: warning.device,
    date: formatDate(language, warning.deviceAdded, now),
  });
}

/** The question below the heading, also the banner's body. */
export function deleteBody(warning: DeleteWarning, t: Translate): string {
  return warning.kind === "massDelete"
    ? t("deletes.body", { count: warning.count, folder: warning.folderName })
    : t("incoming.body");
}

export function MassDeleteDialog({
  warning,
  onClose,
}: {
  readonly warning: DeleteWarning;
  readonly onClose: () => void;
}) {
  const t = useT();
  const language = useLanguage();
  const now = useNow();
  const backend = useBackend();
  const days = useSnapshot().account?.retentionDays ?? 30;
  const titleId = useId();
  const bodyId = useId();
  const hintId = useId();
  const action = useAction();
  const [showList, setShowList] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const incoming = warning.kind === "incomingDelete";
  const more = warning.count - warning.sample.length;
  const title = deleteTitle(warning, t);
  const since = deviceLine(warning, t, language, now);

  const resolve = (decision: "restore" | "delete"): Promise<MassDeleteOutcome> =>
    incoming
      ? backend.resolveIncomingDelete(warning.id, decision)
      : backend.resolveMassDelete(warning.id, decision);

  if (done) {
    return (
      <Dialog labelledBy={titleId} onClose={onClose}>
        <h2 id={titleId} className="dialog-title">
          {title}
        </h2>
        <Feedback>{done}</Feedback>
        <div className="dialog-actions">
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
      size={showList ? "medium" : "small"}
      role="alertdialog"
      closeOnOutside={false}
      onClose={onClose}
    >
      <h2 id={titleId} className="dialog-title">
        {title}
      </h2>
      <div id={bodyId} className="dialog-body">
        {since !== null && <p className="muted">{since}</p>}
        <p>{deleteBody(warning, t)}</p>
        <p className="sample">
          {warning.sample.join(", ")}
          {more > 0 && ` ${t("deletes.sample", { count: more })}`}{" "}
          {!showList && (
            <button
              type="button"
              className="link-button inline"
              onClick={() => {
                setShowList(true);
              }}
            >
              {t("deletes.list")}
            </button>
          )}
        </p>
        {showList && <DeleteList warningId={warning.id} incoming={incoming} />}
        {!incoming && <p className="muted">{t("deletes.kept", { days })}</p>}
      </div>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <button
          type="button"
          className="button danger"
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              // "No" in the native question leaves the dialog as it is.
              const outcome = await resolve("delete");
              if (outcome.kind === "resolved") {
                setDone(t(incoming ? "incoming.done" : "deletes.done", { count: outcome.count }));
              }
            });
          }}
        >
          {t(incoming ? "incoming.confirm" : "deletes.confirm")}
        </button>
        <button
          type="button"
          className="button primary"
          data-autofocus
          aria-describedby={incoming ? hintId : undefined}
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              const outcome = await resolve("restore");
              if (outcome.kind === "resolved") {
                setDone(
                  t(incoming ? "incoming.restored" : "deletes.restored", { count: outcome.count }),
                );
              }
            });
          }}
        >
          {t("deletes.restore")}
        </button>
      </div>
      {incoming && (
        <p id={hintId} className="dialog-foot muted">
          {t("incoming.restoreHint")}
        </p>
      )}
    </Dialog>
  );
}

function DeleteList({
  warningId,
  incoming,
}: {
  readonly warningId: string;
  readonly incoming: boolean;
}) {
  const t = useT();
  const backend = useBackend();
  const [loaded] = useLoad(
    () => (incoming ? backend.listIncomingDelete(warningId) : backend.listMassDelete(warningId)),
    [backend, warningId, incoming],
  );
  if (loaded.status === "loading") return <Loading />;
  if (loaded.status === "failed")
    return <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>;
  return (
    <ul className="scroll-list" tabIndex={0} aria-label={t("deletes.list")}>
      {loaded.data.map((path) => (
        <li key={path} className="bidi-name">
          {displayName(path)}
        </li>
      ))}
    </ul>
  );
}
