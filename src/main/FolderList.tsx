// The folder rows (UX 6.3): name, full path truncated in the middle, status in words with the
// number of files and the size on this disk below it, row menu. As a grid, the same rows are
// cards (the path is the tooltip), and "Add folder" is a dashed card; the choice is kept in the
// shell's settings.
// One tab stop for the list; arrow keys move, Enter opens the folder, Shift+F10 the menu.

import { memo, useEffect, useRef, useState } from "react";

import type { Folder, FolderView, StopReason } from "../backend/types";
import { formatSize } from "../format";
import {
  displayName,
  useLanguage,
  useT,
  type Language,
  type MessageKey,
  type Translate,
} from "../i18n";
import { useBackend } from "../ui/backendContext";
import { FolderIcon, GridIcon, ListIcon, PlusIcon } from "../ui/icons";
import { RowMenu, type MenuItem } from "../ui/Menu";
import { Feedback, PathText } from "../ui/parts";
import { isMenuKey, useRoving } from "../ui/roving";
import { errorText, useAction } from "../ui/useAsync";
import type { Open } from "./openDialog";

/** Why a folder stopped, in words. */
const STOP_REASON_TEXT: Readonly<Record<StopReason, MessageKey>> = {
  missing: "folder.reason.missing",
  olderState: "folder.reason.olderState",
  removedHeads: "folder.reason.removedHeads",
  treeLimit: "folder.reason.treeLimit",
  tooLarge: "folder.reason.tooLarge",
};

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
        reason: t(STOP_REASON_TEXT[status.reason]),
      });
  }
}

/**
 * What the row says about the folder's content: "1.234 Dateien · 6,2 GB". A part that is not
 * known yet (before the first scan, or from an older shell) is left out rather than shown as 0,
 * which would read as empty; null when neither is known.
 */
export function folderContentText(folder: Folder, language: Language, t: Translate): string | null {
  const parts: string[] = [];
  if (folder.fileCount !== null) parts.push(t("folder.files", { count: folder.fileCount }));
  if (folder.bytes !== null) parts.push(formatSize(language, folder.bytes));
  return parts.length === 0 ? null : parts.join(" · ");
}

/**
 * The row's color class: green ("is-ok") only for a folder that is done while the server is
 * reachable, since offline nothing can be confirmed; red ("is-stopped") for every state that
 * needs the person; neutral otherwise.
 */
export function folderTone(folder: Folder, online: boolean): string {
  switch (folder.status.kind) {
    case "upToDate":
      return online ? "is-ok" : "is-quiet";
    case "uploading":
    case "downloading":
      return "is-active";
    case "stopped":
      return "is-stopped";
    case "paused":
      return "is-quiet";
  }
}

/** The folder view of the settings, "list" until they are read; a change is saved at once. */
export function useFolderView(): [FolderView, (view: FolderView) => void] {
  const backend = useBackend();
  const [view, setView] = useState<FolderView>("list");
  // A click before the settings arrive wins over the stored view they bring.
  const chosen = useRef(false);
  useEffect(() => {
    let current = true;
    backend.getSettings().then(
      (settings) => {
        if (current && !chosen.current) setView(settings.folderView);
      },
      () => undefined,
    );
    return () => {
      current = false;
    };
  }, [backend]);
  const change = (next: FolderView) => {
    chosen.current = true;
    setView(next);
    backend.setFolderView(next).catch((error: unknown) => {
      console.error("Hangar Drive: saving the folder view failed", error);
    });
  };
  return [view, change];
}

/** Two icon buttons next to the "Folders" heading; the pressed one is the current view. */
export function FolderViewSwitch({
  view,
  onChange,
}: {
  readonly view: FolderView;
  readonly onChange: (view: FolderView) => void;
}) {
  const t = useT();
  const options = [
    { id: "list", label: t("main.view.list"), icon: <ListIcon size={18} /> },
    { id: "grid", label: t("main.view.grid"), icon: <GridIcon size={18} /> },
  ] as const;
  return (
    <div className="segmented" role="group" aria-label={t("main.view")}>
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          className="segment"
          aria-pressed={view === option.id}
          aria-label={option.label}
          title={option.label}
          onClick={() => {
            onChange(option.id);
          }}
        >
          {option.icon}
        </button>
      ))}
    </div>
  );
}

export function FolderList({
  folders,
  view = "list",
  online,
  open,
  onDeleted,
}: {
  readonly folders: readonly Folder[];
  readonly view?: FolderView;
  /** The server answers; without it no folder is shown as done. */
  readonly online: boolean;
  readonly open: Open;
  /** A folder was deleted everywhere (the person said yes in the native question). */
  readonly onDeleted: (name: string) => void;
}) {
  const t = useT();
  const roving = useRoving(folders.length + 1);
  return (
    <div
      className={view === "grid" ? "folder-list is-grid" : "list folder-list"}
      role="list"
      onKeyDown={roving.onKeyDown}
    >
      {folders.map((folder, index) => (
        <FolderRow
          key={folder.id}
          folder={folder}
          online={online}
          open={open}
          onDeleted={onDeleted}
          index={index}
          tabIndex={roving.tabIndex(index)}
          onItemFocus={roving.onItemFocus}
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

interface FolderRowProps {
  readonly folder: Folder;
  readonly online: boolean;
  readonly open: Open;
  readonly onDeleted: (name: string) => void;
  readonly index: number;
  readonly tabIndex: 0 | -1;
  /** Stable (the roving list's state setter), so a row's props compare equal. */
  readonly onItemFocus: (index: number) => void;
}

/**
 * Whether a row would draw the same: every snapshot brings new folder objects, so the folder is
 * compared by its content (a few short fields), the rest by identity.
 */
export function sameRowProps(a: FolderRowProps, b: FolderRowProps): boolean {
  return (
    a.online === b.online &&
    a.open === b.open &&
    a.onDeleted === b.onDeleted &&
    a.index === b.index &&
    a.tabIndex === b.tabIndex &&
    a.onItemFocus === b.onItemFocus &&
    (a.folder === b.folder || JSON.stringify(a.folder) === JSON.stringify(b.folder))
  );
}

// A snapshot arrives for every slice of the engine's work; only the rows whose folder changed
// draw again.
const FolderRow = memo(FolderRowView, sameRowProps);

function FolderRowView({
  folder,
  online,
  open,
  onDeleted,
  index,
  tabIndex,
  onItemFocus,
}: FolderRowProps) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const action = useAction();
  const [menuOpen, setMenuOpen] = useState(false);
  const main = useRef<HTMLButtonElement>(null);
  const status = folderStatusText(folder, t);
  const size = folderContentText(folder, language, t);
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
    <div role="listitem" className={`row folder-row ${folderTone(folder, online)}`}>
      <div className="row-line">
        <button
          ref={main}
          type="button"
          className="row-main"
          data-roving
          tabIndex={tabIndex}
          aria-label={[folder.name, displayName(folder.path), status, size]
            .filter(Boolean)
            .join(", ")}
          title={displayName(folder.path)}
          onFocus={() => {
            onItemFocus(index);
          }}
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
          <span className="row-end">
            <span className="row-status">{status}</span>
            {size !== null && <span className="row-size">{size}</span>}
          </span>
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
