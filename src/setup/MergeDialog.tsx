// "The chosen folder is not empty" (UX 6.5): the number of local files first, because it tells a
// person whether they picked the right place. "Merge" loses nothing and is the default; Escape
// goes back and nothing is uploaded.

import { useId, useState } from "react";

import type { FolderId } from "../backend/types";
import { useT } from "../i18n";
import { folderRefusalText } from "../main/BannerArea";
import { useBackend } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { FolderIcon } from "../ui/icons";
import { Feedback, PathText } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

interface Props {
  readonly folderId: FolderId;
  readonly folderName: string;
  readonly path: string;
  readonly onMerge: (path: string) => Promise<void>;
  readonly onClose: () => void;
}

export function MergeDialog({ folderId, folderName, path: initialPath, onMerge, onClose }: Props) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const bodyId = useId();
  const [path, setPath] = useState(initialPath);
  const [message, setMessage] = useState<string | null>(null);
  const action = useAction();
  const [count] = useLoad(() => backend.countLocalFiles(path), [backend, path]);

  const known = count.status === "ready" ? count.data : null;
  return (
    <Dialog labelledBy={titleId} describedBy={bodyId} onClose={onClose} role="alertdialog">
      <h2 id={titleId} className="dialog-title">
        {known === null ? t("merge.counting") : t("merge.title", { count: known })}
      </h2>
      <div id={bodyId} className="dialog-body">
        {known !== null && <p>{t("merge.body", { count: known, folder: folderName })}</p>}
        <p className="place">
          <FolderIcon />
          <PathText path={path} />
        </p>
      </div>
      {count.status === "failed" && <Feedback tone="error">{errorText(count.error, t)}</Feedback>}
      {message && <Feedback tone="error">{message}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            setMessage(null);
            void action.run(async () => {
              const result = await backend.pickFolder({ kind: "account", folderId });
              if (result.kind === "picked") setPath(result.path);
              if (result.kind === "refused") {
                setMessage(folderRefusalText(result.reason, result.folder, t));
              }
            });
          }}
        >
          {t("merge.chooseOther")}
        </button>
        <button
          type="button"
          className="button primary"
          data-autofocus
          aria-disabled={known === null || action.pending}
          onClick={() => {
            if (known === null) return;
            void action.run(() => onMerge(path));
          }}
        >
          {t("merge.confirm")}
        </button>
      </div>
    </Dialog>
  );
}
