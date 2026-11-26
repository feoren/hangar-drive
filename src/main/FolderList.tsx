// The folder rows (UX 6.3): name, full path truncated in the middle, status in words, row menu.
// One tab stop for the list; arrow keys move, Enter opens the folder, Shift+F10 the menu.

import { useRef, useState } from "react";

import type { Folder } from "../backend/types";
import { useT, type Translate } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { FolderIcon, PlusIcon } from "../ui/icons";
import { RowMenu, type MenuItem } from "../ui/Menu";
import { Feedback, PathText } from "../ui/parts";
import { isMenuKey, useRoving } from "../ui/roving";
import { errorText, useAction } from "../ui/useAsync";
import type { Open } from "./openDialog";

export function folderStatusText(folder: Folder, t: Translate): string {
  const status = folder.status;
  switch (status.kind) {
    case "upToDate":
      return t("folder.status.upToDate");
    case "uploading":
      return t("folder.status.uploading", { count: status.count });
    case "downloading":
      return t("folder.status.downloading", { count: status.count });
    case "paused":
      return t("folder.status.paused");
    case "stopped":
      return t("folder.status.stopped", {
        reason: t(
          status.reason === "missing"
            ? "folder.reason.missing"
            : status.reason === "olderState"
              ? "folder.reason.olderState"
              : "folder.reason.removedHeads",
        ),
      });
  }
}

function statusTone(folder: Folder): string {
  switch (folder.status.kind) {
    case "uploading":
    case "downloading":
      return "is-active";
    case "stopped":
      return "is-stopped";
    default:
      return "is-quiet";
  }
}

export function FolderList({
  folders,
  open,
  onDeleted,
}: {
  readonly folders: readonly Folder[];
  readonly open: Open;
  /** A folder was deleted everywhere (the person said yes in the native question). */
  readonly onDeleted: (name: string) => void;
}) {
  const t = useT();
  const roving = useRoving(folders.length + 1);
  return (
    <div className="list folder-list" role="list" onKeyDown={roving.onKeyDown}>
      {folders.map((folder, index) => (
        <FolderRow
          key={folder.id}
          folder={folder}
          open={open}
          onDeleted={onDeleted}
          tabIndex={roving.tabIndex(index)}
          onFocus={() => {
            roving.onItemFocus(index);
          }}
        />
      ))}
      <div role="listitem" className="row add-row">
        <button
          type="button"
          className="row-main add-folder"
          data-roving
          tabIndex={roving.tabIndex(folders.length)}
          onFocus={() => {
            roving.onItemFocus(folders.length);
          }}
          onClick={() => {
            open({ kind: "addFolder" });
          }}
        >
          <span className="row-icon">
            <PlusIcon />
          </span>
          <span className="row-name">{t("main.addFolder")}</span>
        </button>
      </div>
    </div>
  );
}

function FolderRow({
  folder,
  open,
  onDeleted,
  tabIndex,
  onFocus,
}: {
  readonly folder: Folder;
  readonly open: Open;
  readonly onDeleted: (name: string) => void;
  readonly tabIndex: 0 | -1;
  readonly onFocus: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const [menuOpen, setMenuOpen] = useState(false);
  const main = useRef<HTMLButtonElement>(null);
  const status = folderStatusText(folder, t);
  const paused = folder.status.kind === "paused";

  const openInExplorer = () => {
    void action.run(() => backend.openFolder(folder.id));
  };

  const items: MenuItem[] = [
    { id: "open", label: t("folder.menu.open"), onSelect: openInExplorer },
    {
      id: "versions",
      label: t("folder.menu.versions"),
      onSelect: () => {
        open({ kind: "restore", folderId: folder.id, tab: "versions" });
      },
    },
    {
      id: "trash",
      label: t("folder.menu.trash"),
      onSelect: () => {
        open({ kind: "restore", folderId: folder.id, tab: "trash" });
      },
    },
    {
      id: "pause",
      label: paused ? t("folder.menu.resume") : t("folder.menu.pause"),
      onSelect: () => {
        void action.run(() =>
          paused ? backend.resumeFolder(folder.id) : backend.pauseFolder(folder.id),
        );
      },
    },
    {
      id: "number",
      label: t("folder.menu.number"),
      onSelect: () => {
        open({ kind: "folderNumber", folder });
      },
    },
    {
      id: "stop",
      label: t("folder.menu.stop"),
      onSelect: () => {
        open({ kind: "stopFolder", folder });
      },
    },
    {
      id: "delete",
      label: t("folder.menu.delete"),
      danger: true,
      separated: true,
      // No question of the window's own: the shell asks natively and names the folder (security
      // review L2), so a second question here would only make the person answer twice.
      onSelect: () => {
        void action.run(async () => {
          const outcome = await backend.deleteFolderEverywhere(folder.id);
          if (outcome === "deleted") onDeleted(folder.name);
        });
      },
    },
  ];

  return (
    <div role="listitem" className={`row folder-row ${statusTone(folder)}`}>
      <div className="row-line">
        <button
          ref={main}
          type="button"
          className="row-main"
          data-roving
          tabIndex={tabIndex}
          aria-label={`${folder.name}, ${folder.path}, ${status}`}
          title={folder.path}
          onFocus={onFocus}
          onDoubleClick={openInExplorer}
          onClick={(event) => {
            // A single click only selects; Enter and a double click open (Explorer habit).
            if (event.detail === 0) openInExplorer();
          }}
          onKeyDown={(event) => {
            if (isMenuKey(event)) {
              event.preventDefault();
              setMenuOpen(true);
            }
          }}
        >
          <span className="row-icon">
            <FolderIcon />
          </span>
          <span className="row-text">
            <span className="row-name">{folder.name}</span>
            <PathText path={folder.path} className="row-sub" />
          </span>
          <span className="row-status">{status}</span>
        </button>
        <RowMenu
          items={items}
          label={t("main.rowMenu", { name: folder.name })}
          open={menuOpen}
          onOpenChange={setMenuOpen}
          returnFocus={main}
        />
      </div>
      {folder.freezeDays !== null && (
        <p className="row-note">
          {t("freeze.line", { days: folder.freezeDays })}{" "}
          <button
            type="button"
            className="link-button"
            onClick={() => {
              open({ kind: "folderNumber", folder });
            }}
          >
            {t("freeze.compare")}
          </button>
        </p>
      )}
      {folder.notSyncedCount > 0 && (
        <p className="row-note">
          <button
            type="button"
            className="link-button"
            onClick={() => {
              open({ kind: "notSynced", folder });
            }}
          >
            {t("names.notSynced", { count: folder.notSyncedCount })}
          </button>
        </p>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
    </div>
  );
}
