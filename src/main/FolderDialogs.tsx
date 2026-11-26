// Dialogs of the folder rows: stop syncing, folder number, entries that are never synced, and
// "Add folder". Neither "Delete everywhere" nor joining a folder that is not empty (6.5) has a
// dialog of its own: the shell asks natively (security review L2, H1), see FolderList and
// `bring` below.

import { useId, useState } from "react";

import type { Folder, FolderId, FolderPlace } from "../backend/types";
import { useT } from "../i18n";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Dialog } from "../ui/Dialog";
import { FolderIcon, PlusIcon } from "../ui/icons";
import { Feedback, Loading, NumberRows } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
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

/** "Add folder" (UX 6.3): folders of the other devices first, then any folder here. */
export function AddFolderDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const titleId = useId();
  const action = useAction();
  const [message, setMessage] = useState<string | null>(null);

  /**
   * The backend proposes the place (and its token) right when the person asks, so a folder that
   * appeared a moment ago has one too. Without a proposal the person picks the place.
   */
  const placeFor = async (folderId: FolderId): Promise<FolderPlace | null> => {
    const proposals = await backend.listAccountFolders();
    const found = proposals.folders.find((folder) => folder.id === folderId);
    if (found) return { path: found.proposedPath, name: found.name, token: found.proposedToken };
    const picked = await backend.pickFolder({ kind: "account", folderId });
    if (picked.kind === "refused") setMessage(folderRefusalText(picked.reason, picked.folder, t));
    return picked.kind === "picked" ? picked : null;
  };

  /**
   * Joins the folder at `token`. A place that holds files is asked about natively by the shell
   * (6.5, security review H1); "Choose another folder" there opens the picker and tries again.
   */
  const join = async (folderId: FolderId, token: string): Promise<void> => {
    const outcome = await backend.addAccountFolder(folderId, token);
    if (outcome === "joined") {
      onClose();
      return;
    }
    const picked = await backend.pickFolder({ kind: "account", folderId });
    if (picked.kind === "refused") setMessage(folderRefusalText(picked.reason, picked.folder, t));
    if (picked.kind === "picked") await join(folderId, picked.token);
  };

  const bring = (folderId: FolderId) => {
    setMessage(null);
    void action.run(async () => {
      const place = await placeFor(folderId);
      if (place) await join(folderId, place.token);
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
      await backend.addFolder(result.token);
      onClose();
    });
  };

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
                    bring(folder.id);
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
