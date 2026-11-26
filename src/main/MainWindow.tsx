// The main window (UX 6.3): status first, then the one banner, the folders, recent activity and
// the quiet lines at the bottom. The header buttons come last in the tab order (UX 12), so the
// header follows the content in the document and is placed on top by the layout.

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";

import type { FocusRequest, HeadsRequest, IncomingLink } from "../App";
import { cleanLink, linkKind } from "../domain/links";
import { shownWarnings, type ShownWarning } from "../domain/warnings";
import { formatSize } from "../format";
import { useLanguage, useT } from "../i18n";
import { MassDeleteDialog } from "../problems/MassDeleteDialog";
import { ConflictsDialog } from "../problems/ConflictsDialog";
import { NamesDialog } from "../problems/NamesDialog";
import { RemovedHeadsDialog } from "../problems/RemovedHeadsDialog";
import { ReanchorDialog } from "../problems/ReanchorDialog";
import { ServerCompareDialog, ServerScanDialog } from "../problems/ServerDialogs";
import { NotMeDialog, SuspectDialog } from "../problems/SuspectDialog";
import { RestoreDialog } from "../restore/RestoreDialog";
import { DevicesDialog } from "../devices/DevicesDialog";
import { HelpDialog, noticeText, SettingsDialog } from "../settings/SettingsDialog";
import { PairFlow } from "../setup/PairFlow";
import { shortcutFor } from "../shortcuts";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback } from "../ui/parts";
import { DevicesIcon, GearIcon, HelpIcon, PlusIcon } from "../ui/icons";
import { BrandMark } from "../ui/StatusMark";
import { ActivityList } from "./ActivityList";
import { BannerArea } from "./BannerArea";
import {
  AddFolderDialog,
  FolderNumberDialog,
  NotSyncedDialog,
  StopFolderDialog,
} from "./FolderDialogs";
import { FolderList } from "./FolderList";
import type { OpenDialog } from "./openDialog";
import { StatusHeader } from "./StatusHeader";

/** The storage line appears only above this share of the quota (UX 6.3). */
export const STORAGE_LINE_SHARE = 0.8;

/**
 * What a link the OS handed over means on a device that is set up: a pairing link mends a server
 * that identifies itself differently or pairs a removed device again; anything else is not needed.
 */
export function dialogForLink(text: string, warnings: readonly ShownWarning[]): OpenDialog | null {
  const kind = linkKind(text);
  if (kind === null) return null;
  const link = cleanLink(text);
  if (kind === "pair") {
    if (warnings.some((warning) => warning.kind === "serverIdentity")) {
      return { kind: "serverScan", link };
    }
    if (warnings.some((warning) => warning.kind === "removed" || warning.kind === "refused")) {
      return { kind: "repair", link };
    }
  }
  return { kind: "linkNotNeeded" };
}

export function MainWindow({
  focus,
  link = null,
  heads = null,
}: {
  readonly focus: FocusRequest;
  readonly link?: IncomingLink | null;
  readonly heads?: HeadsRequest | null;
}) {
  const t = useT();
  const language = useLanguage();
  const snapshot = useSnapshot();
  const now = useNow();
  const [dialog, setDialog] = useState<OpenDialog | null>(null);
  /** The folder just deleted everywhere, for the line that says how to bring it back. */
  const [deleted, setDeleted] = useState<string | null>(null);
  const banner = useRef<HTMLDivElement>(null);
  // A dialog the window opened by itself gives the focus back to the banner, not to whatever had
  // it by chance (UX 8.1: Escape leaves the decision open, the banner stays).
  const focusBanner = useRef(false);
  const open = useCallback((next: OpenDialog) => {
    setDeleted(null);
    setDialog(next);
  }, []);
  const close = () => {
    if (dialog && "auto" in dialog && dialog.auto) focusBanner.current = true;
    setDialog(null);
  };
  useLayoutEffect(() => {
    if (dialog || !focusBanner.current) return;
    focusBanner.current = false;
    banner.current?.focus();
  }, [dialog]);
  const warnings = shownWarnings(snapshot, now);
  const danger = warnings.some((warning) => warning.kind === "suspect");

  const [handledLink, setHandledLink] = useState(0);
  if (link && link.at !== handledLink) {
    setHandledLink(link.at);
    const next = dialogForLink(link.link, warnings);
    if (next) setDialog(next);
  }

  // Global shortcuts, only while no dialog is open (dialogs keep their keys to themselves).
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (dialog || event.defaultPrevented) return;
      const id = shortcutFor(event);
      if (!id) return;
      event.preventDefault();
      setDialog({ kind: id });
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [dialog]);

  const storage = snapshot.storage;
  const showStorage =
    storage !== null && storage.quota > 0 && storage.used / storage.quota >= STORAGE_LINE_SHARE;

  return (
    <div className="window">
      <main className="main">
        <div className="column">
          <StatusHeader danger={danger} />
          <BannerArea open={open} focus={focus} heads={heads} region={banner} />
          <section className="section" aria-labelledby="folders-title">
            <h2 id="folders-title" className="section-title">
              {t("main.folders")}
            </h2>
            {snapshot.folders.length === 0 ? (
              <div className="empty">
                <p className="empty-title">{t("main.empty.title")}</p>
                <p className="empty-body">{t("main.empty.body")}</p>
                <button
                  type="button"
                  className="button primary with-icon"
                  onClick={() => {
                    open({ kind: "addFolder" });
                  }}
                >
                  <PlusIcon size={18} />
                  {t("main.addFolder")}
                </button>
              </div>
            ) : (
              <FolderList folders={snapshot.folders} open={open} onDeleted={setDeleted} />
            )}
            {deleted !== null && (
              <Feedback>
                {`${t("folder.deleted.done", { folder: deleted })} ${t("folder.delete.body", {
                  days: snapshot.account?.retentionDays ?? 30,
                })}`}
              </Feedback>
            )}
          </section>
          <section className="section" aria-labelledby="activity-title">
            <h2 id="activity-title" className="section-title">
              {t("main.activity")}
            </h2>
            <ActivityList entries={snapshot.activity} open={open} />
          </section>
          {(showStorage || snapshot.notices.length > 0) && (
            <footer className="quiet-lines">
              {showStorage && (
                <p>
                  {t("main.storage", {
                    used: formatSize(language, storage.used),
                    quota: formatSize(language, storage.quota),
                  })}
                </p>
              )}
              {snapshot.notices.map((notice) => (
                <p key={notice.kind}>{noticeText(notice, t)}</p>
              ))}
            </footer>
          )}
        </div>
      </main>
      <header className="topbar">
        <div className="brand">
          <BrandMark size={20} className="brand-mark" />
          <span className="brand-name">{t("app.name")}</span>
        </div>
        <nav className="topbar-actions" aria-label={t("app.name")}>
          <button
            type="button"
            className="quiet-button"
            onClick={() => {
              open({ kind: "devices" });
            }}
          >
            <DevicesIcon size={18} />
            <span>{t("main.devices")}</span>
          </button>
          <button
            type="button"
            className="quiet-button"
            onClick={() => {
              open({ kind: "settings" });
            }}
          >
            <GearIcon size={18} />
            <span>{t("main.settings")}</span>
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label={t("help.title")}
            title={t("help.title")}
            onClick={() => {
              open({ kind: "help" });
            }}
          >
            <HelpIcon size={18} />
          </button>
        </nav>
      </header>
      {dialog && <DialogHost dialog={dialog} open={open} onClose={close} />}
    </div>
  );
}

function DialogHost({
  dialog,
  open,
  onClose,
}: {
  readonly dialog: OpenDialog;
  readonly open: (dialog: OpenDialog) => void;
  readonly onClose: () => void;
}) {
  switch (dialog.kind) {
    case "devices":
      return <DevicesDialog onClose={onClose} />;
    case "settings":
      return <SettingsDialog onClose={onClose} />;
    case "help":
      return <HelpDialog onClose={onClose} />;
    case "restore":
      return (
        <RestoreDialog
          folderId={dialog.folderId}
          tab={dialog.tab}
          entryId={dialog.entryId}
          path={dialog.path}
          beforeDevice={dialog.beforeDevice}
          onClose={onClose}
        />
      );
    case "conflicts":
      return <ConflictsDialog onClose={onClose} />;
    case "names":
      return <NamesDialog onClose={onClose} />;
    case "massDelete":
      return <MassDeleteDialog warning={dialog.warning} onClose={onClose} />;
    case "removedHeads":
      return <RemovedHeadsDialog warning={dialog.warning} open={open} onClose={onClose} />;
    case "linkNotNeeded":
      return <LinkNotNeededDialog onClose={onClose} />;
    case "stopFolder":
      return <StopFolderDialog folder={dialog.folder} onClose={onClose} />;

    case "folderNumber":
      return <FolderNumberDialog folder={dialog.folder} onClose={onClose} />;
    case "notSynced":
      return <NotSyncedDialog folder={dialog.folder} onClose={onClose} />;
    case "addFolder":
      return <AddFolderDialog onClose={onClose} />;
    case "serverScan":
      return <ServerScanDialog initialLink={dialog.link} onClose={onClose} />;
    case "serverCompare":
      return <ServerCompareDialog onClose={onClose} />;
    case "reanchor":
      return (
        <ReanchorDialog
          folderId={dialog.folderId}
          folderName={dialog.folderName}
          onClose={onClose}
        />
      );
    case "suspect":
      return <SuspectDialog warning={dialog.warning} open={open} onClose={onClose} />;
    case "notMe":
      return <NotMeDialog onClose={onClose} />;
    case "repair":
      return <RepairDialog initialLink={dialog.link} onClose={onClose} />;
  }
}

/** "Pair again" after this device was removed or refused (UX 8.8): the pairing of 4.3. */
function RepairDialog({
  initialLink,
  onClose,
}: {
  readonly initialLink: string | undefined;
  readonly onClose: () => void;
}) {
  const backend = useBackend();
  return (
    <Dialog labelledBy="repair-title" size="large" onClose={onClose} closeOnOutside={false}>
      <PairFlow
        titleId="repair-title"
        initialLink={initialLink ?? ""}
        onBack={onClose}
        onDone={() => {
          backend.getSnapshot().catch(() => undefined);
          onClose();
        }}
      />
    </Dialog>
  );
}

/** A link opened on a device that is already set up: say so, nothing happens (UX 4). */
function LinkNotNeededDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const titleId = useId();
  return (
    <Dialog labelledBy={titleId} onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("link.notNeeded.title")}
      </h2>
      <p className="dialog-body">{t("link.notNeeded.body")}</p>
      <div className="dialog-actions">
        <button type="button" className="button primary" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}
