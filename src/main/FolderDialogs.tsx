// Dialogs of the folder rows: stop syncing, delete everywhere, folder number, entries that are
// never synced, and "Add folder" with the merge question for a folder that is not empty (6.5).

import { useId, useState } from "react";

import type { Folder, FolderId } from "../backend/types";
import { useT } from "../i18n";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Dialog } from "../ui/Dialog";
import { FolderIcon, PlusIcon } from "../ui/icons";
import { Feedback, Loading, NumberRows } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { MergeDialog } from "../setup/MergeDialog";
import { folderRefusalText } from "./BannerArea";

export function StopFolderDialog({
  folder,
  onClose,
}: {
  readonly folder: Folder;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  return (
    <ConfirmDialog
      title={t("folder.stop.title", { folder: folder.name })}
      confirmLabel={t("folder.stop.confirm")}
      onConfirm={() => backend.stopFolder(folder.id)}
      onClose={onClose}
    >
      <p>{t("folder.stop.body")}</p>
    </ConfirmDialog>
  );
}

export function DeleteFolderDialog({
  folder,
  onClose,
}: {
  readonly folder: Folder;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const days = useSnapshot().account?.retentionDays ?? 30;
  return (
    <ConfirmDialog
      title={t("folder.delete.title", { folder: folder.name })}
      confirmLabel={t("folder.delete.confirm")}
      danger
      onConfirm={() => backend.deleteFolderEverywhere(folder.id)}
      onClose={onClose}
    >
      <p>{t("folder.delete.body", { days })}</p>
    </ConfirmDialog>
  );
}

export function FolderNumberDialog({
  folder,
  onClose,
}: {
  readonly folder: Folder;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const [loaded] = useLoad(() => backend.getFolderNumber(folder.id), [backend, folder.id]);
  return (
    <Dialog labelledBy={titleId} onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("folder.number.title", { folder: folder.name })}
      </h2>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {loaded.status === "ready" &&
        (loaded.data.kind === "offline" ? (
          <p className="dialog-body">{t("folder.number.offline", { app: t("app.name") })}</p>
        ) : (
          <>
            <p className="dialog-body">
              {folder.freezeDays !== null ? t("freeze.compareBody") : t("folder.number.body")}
            </p>
            <NumberRows rows={loaded.data.number} label={t("folder.menu.number")} />
          </>
        ))}
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

export function NotSyncedDialog({
  folder,
  onClose,
}: {
  readonly folder: Folder;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const [loaded] = useLoad(() => backend.listNotSynced(folder.id), [backend, folder.id]);
  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("names.notSynced", { count: folder.notSyncedCount })}
      </h2>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {loaded.status === "ready" && (
        <ul className="plain-list">
          {loaded.data.map((entry) => (
            <li key={entry.path} className="plain-item">
              <span className="plain-name">{entry.path}</span>
              <span className="plain-sub">
                {entry.reason === "link" ? t("names.notSynced.link") : t("names.notSynced.system")}
              </span>
            </li>
          ))}
        </ul>
      )}
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

type Pending = { readonly folderId: FolderId; readonly name: string; readonly path: string };

/** "Add folder" (UX 6.3): folders of the other devices first, then any folder here. */
export function AddFolderDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const titleId = useId();
  const action = useAction();
  const [message, setMessage] = useState<string | null>(null);
  const [merge, setMerge] = useState<Pending | null>(null);
  const [proposals] = useLoad(() => backend.listAccountFolders(), [backend]);

  const proposedPath = (folderId: FolderId, name: string): string => {
    if (proposals.status === "ready") {
      const found = proposals.data.folders.find((folder) => folder.id === folderId);
      if (found) return found.proposedPath;
    }
    const home = snapshot.folders[0]?.path.replace(/[\\/][^\\/]*$/, "");
    return home ? `${home}\\${name}` : name;
  };

  const bring = (folderId: FolderId, name: string) => {
    setMessage(null);
    void action.run(async () => {
      const path = proposedPath(folderId, name);
      const count = await backend.countLocalFiles(path);
      if (count > 0) {
        setMerge({ folderId, name, path });
        return;
      }
      await backend.addAccountFolder(folderId, path);
      onClose();
    });
  };

  const chooseOther = () => {
    setMessage(null);
    void action.run(async () => {
      const result = await backend.pickFolder({ kind: "new" });
      if (result.kind === "cancelled") return;
      if (result.kind === "refused") {
        setMessage(folderRefusalText(result.reason, result.folder, t));
        return;
      }
      await backend.addFolder(result.path);
      onClose();
    });
  };

  if (merge) {
    return (
      <MergeDialog
        folderId={merge.folderId}
        folderName={merge.name}
        path={merge.path}
        onMerge={async (path) => {
          await backend.addAccountFolder(merge.folderId, path);
          onClose();
        }}
        onClose={() => {
          setMerge(null);
        }}
      />
    );
  }

  const remote = snapshot.remoteFolders;
  const deleted = snapshot.deletedFolders;
  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("main.addFolder")}
      </h2>
      {remote.length > 0 && (
        <section className="dialog-section">
          <h3 className="section-label">{t("main.addFolder.remote")}</h3>
          <ul className="plain-list">
            {remote.map((folder) => (
              <li key={folder.id} className="plain-item with-action">
                <FolderIcon />
                <span className="plain-name">{folder.name}</span>
                <button
                  type="button"
                  className="button secondary small"
                  disabled={action.pending}
                  onClick={() => {
                    bring(folder.id, folder.name);
                  }}
                >
                  {t("main.addFolder.bring")}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
      {deleted.length > 0 && (
        <section className="dialog-section">
          <h3 className="section-label">{t("folder.deleted.section")}</h3>
          <ul className="plain-list">
            {deleted.map((folder) => (
              <li key={folder.id} className="plain-item with-action">
                <FolderIcon />
                <span className="plain-name">
                  {folder.name}
                  <span className="plain-sub">
                    {" "}
                    {t("folder.deleted.daysLeft", { days: folder.daysLeft })}
                  </span>
                </span>
                <button
                  type="button"
                  className="button secondary small"
                  disabled={action.pending}
                  onClick={() => {
                    void action.run(() => backend.restoreDeletedFolder(folder.id));
                  }}
                >
                  {t("folder.deleted.restore")}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
      <div className="dialog-section">
        <button
          type="button"
          className="button secondary with-icon"
          data-autofocus={remote.length === 0 ? true : undefined}
          disabled={action.pending}
          onClick={chooseOther}
        >
          <PlusIcon size={18} />
          {remote.length + deleted.length > 0 ? t("main.addFolder.new") : t("main.addFolder")}
        </button>
      </div>
      {message && <Feedback tone="error">{message}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}
