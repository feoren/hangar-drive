// Recent activity (UX 6.3): the last events of this device, newest first, in a view of the main
// menu. Enter or a double click shows the file in Explorer; the row menu has "Earlier versions".

import { useId, useRef, useState } from "react";

import type { ActivityEntry } from "../backend/types";
import { formatRelative } from "../format";
import { displayName, useLanguage, useT, type Translate } from "../i18n";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { FileIcon, FolderIcon } from "../ui/icons";
import { RowMenu } from "../ui/Menu";
import { Feedback } from "../ui/parts";
import { isMenuKey, useRoving } from "../ui/roving";
import { errorText, useAction } from "../ui/useAsync";
import type { Open } from "./openDialog";

function describe(entry: ActivityEntry, t: Translate): { title: string; what: string | null } {
  switch (entry.kind) {
    case "file": {
      const what =
        entry.action === "fromDevice"
          ? t("activity.fromDevice", { device: entry.device ?? "" })
          : t(`activity.${entry.action}`);
      return { title: displayName(entry.name), what };
    }
    case "group":
      return {
        title: t("activity.group", { folder: entry.folderName, count: entry.count }),
        what: null,
      };
    case "remoteDeleted":
      return {
        title: t("activity.remoteDeleted", {
          folder: entry.folderName,
          count: entry.count,
          device: entry.device,
        }),
        what: null,
      };
    case "cameBack":
      return {
        title: t("activity.cameBack", { name: entry.name, device: entry.device }),
        what: null,
      };
  }
}

export function ActivityList({
  entries,
  open,
}: {
  readonly entries: readonly ActivityEntry[];
  readonly open: Open;
}) {
  const t = useT();
  const roving = useRoving(entries.length);
  if (entries.length === 0) return <p className="empty-line">{t("main.activity.empty")}</p>;
  return (
    <div className="list activity-list" role="list" onKeyDown={roving.onKeyDown}>
      {entries.map((entry, index) => (
        <ActivityRow
          key={entry.id}
          entry={entry}
          open={open}
          tabIndex={roving.tabIndex(index)}
          onFocus={() => {
            roving.onItemFocus(index);
          }}
        />
      ))}
    </div>
  );
}

function ActivityRow({
  entry,
  open,
  tabIndex,
  onFocus,
}: {
  readonly entry: ActivityEntry;
  readonly open: Open;
  readonly tabIndex: 0 | -1;
  readonly onFocus: () => void;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const now = useNow();
  const action = useAction();
  const [menuOpen, setMenuOpen] = useState(false);
  const [restored, setRestored] = useState<number | null>(null);
  const main = useRef<HTMLButtonElement>(null);
  const { title, what } = describe(entry, t);
  const when = formatRelative(language, entry.at, now);
  const path = entry.kind === "file" || entry.kind === "cameBack" ? entry.path : undefined;
  const reveal = () => {
    void action.run(() => backend.openFolder(entry.folderId, path));
  };
  const hasFile = entry.kind === "file" || entry.kind === "cameBack";
  const folderName = hasFile ? displayName(entry.folderName) : null;
  const label = [title, folderName, what, when].filter(Boolean).join(", ");

  return (
    <div role="listitem" className="row activity-row">
      <div className="row-line">
        <button
          ref={main}
          type="button"
          className="row-main"
          data-roving
          tabIndex={tabIndex}
          aria-label={label}
          onFocus={onFocus}
          onDoubleClick={reveal}
          onClick={(event) => {
            if (event.detail === 0) reveal();
          }}
          onKeyDown={(event) => {
            if (hasFile && isMenuKey(event)) {
              event.preventDefault();
              setMenuOpen(true);
            }
          }}
        >
          <span className="row-icon small">
            {hasFile ? <FileIcon size={18} /> : <FolderIcon size={18} />}
          </span>
          <span className={hasFile ? "activity-name" : "activity-name wide"} title={title}>
            {title}
          </span>
          {hasFile && <span className="activity-folder">{folderName}</span>}
          {what && <span className="activity-what">{what}</span>}
          <span className="activity-when">{when}</span>
        </button>
        {hasFile && path !== undefined ? (
          <RowMenu
            items={[
              { id: "show", label: t("folder.menu.open"), onSelect: reveal },
              {
                id: "versions",
                label: t("folder.menu.versions"),
                onSelect: () => {
                  open({ kind: "restore", folderId: entry.folderId, tab: "versions", path });
                },
              },
            ]}
            label={t("main.rowMenu", { name: title })}
            open={menuOpen}
            onOpenChange={setMenuOpen}
            returnFocus={main}
          />
        ) : (
          <span className="row-menu-spacer" />
        )}
      </div>
      {entry.kind === "remoteDeleted" && restored === null && (
        <p className="row-note">
          <button
            type="button"
            className="link-button inline"
            disabled={action.pending}
            onClick={() => {
              void action.run(async () => {
                setRestored(await backend.restoreRemoteDeleted(entry.id));
              });
            }}
          >
            {t("deletes.restore")}
          </button>
        </p>
      )}
      {restored !== null && <Feedback>{t("deletes.restored", { count: restored })}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
    </div>
  );
}

/** Recent activity as its own view from the main menu, in the style of the devices view. */
export function ActivityDialog({
  open,
  onClose,
}: {
  readonly open: Open;
  readonly onClose: () => void;
}) {
  const t = useT();
  const snapshot = useSnapshot();
  const titleId = useId();
  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <div className="view-head">
        <h2 id={titleId} className="dialog-title">
          {t("main.activity")}
        </h2>
      </div>
      <div className="view-body">
        <ActivityList entries={snapshot.activity} open={open} />
      </div>
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}
