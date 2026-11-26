// Many deletions at once (UX 8.1): only the deletions wait. "Restore" has the focus because it
// loses nothing; "Yes, delete" is the danger style. Escape closes without deciding.

import { useId, useState } from "react";

import type { Warning } from "../backend/types";
import { useT } from "../i18n";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

export function MassDeleteDialog({
  warning,
  onClose,
}: {
  readonly warning: Extract<Warning, { kind: "massDelete" }>;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const days = useSnapshot().account?.retentionDays ?? 30;
  const titleId = useId();
  const bodyId = useId();
  const action = useAction();
  const [showList, setShowList] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const more = warning.count - warning.sample.length;

  if (done) {
    return (
      <Dialog labelledBy={titleId} onClose={onClose}>
        <h2 id={titleId} className="dialog-title">
          {t("deletes.title", { count: warning.count })}
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
        {t("deletes.title", { count: warning.count })}
      </h2>
      <div id={bodyId} className="dialog-body">
        <p>{t("deletes.body", { count: warning.count, folder: warning.folderName })}</p>
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
        {showList && <DeleteList warningId={warning.id} />}
        <p className="muted">{t("deletes.kept", { days })}</p>
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
              const outcome = await backend.resolveMassDelete(warning.id, "delete");
              if (outcome.kind === "resolved") setDone(t("deletes.done", { count: outcome.count }));
            });
          }}
        >
          {t("deletes.confirm")}
        </button>
        <button
          type="button"
          className="button primary"
          data-autofocus
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              const outcome = await backend.resolveMassDelete(warning.id, "restore");
              if (outcome.kind === "resolved") {
                setDone(t("deletes.restored", { count: outcome.count }));
              }
            });
          }}
        >
          {t("deletes.restore")}
        </button>
      </div>
    </Dialog>
  );
}

function DeleteList({ warningId }: { readonly warningId: string }) {
  const t = useT();
  const backend = useBackend();
  const [loaded] = useLoad(() => backend.listMassDelete(warningId), [backend, warningId]);
  if (loaded.status === "loading") return <Loading />;
  if (loaded.status === "failed")
    return <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>;
  return (
    <ul className="scroll-list" tabIndex={0} aria-label={t("deletes.list")}>
      {loaded.data.map((path) => (
        <li key={path}>{path}</li>
      ))}
    </ul>
  );
}
