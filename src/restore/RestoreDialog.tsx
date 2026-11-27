// Earlier versions and trash of a folder (UX 9): one view with two tabs, so there is one place to
// learn. The timeline is a listbox grouped by day; arrow keys move and the right side updates at
// once. In a narrow window the timeline folds to the chosen entry (UX 12).

import { useEffect, useId, useMemo, useRef, useState } from "react";

import type { FolderId, RestoreOutcome, Timeline, TimelineEntry, TreeNode } from "../backend/types";
import { formatRelative, formatTime } from "../format";
import { displayName, useLanguage, useT } from "../i18n";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { FileIcon, FolderIcon, SearchIcon } from "../ui/icons";
import { RowMenu } from "../ui/Menu";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import {
  dayHeading,
  diffText,
  entrySummary,
  groupByDay,
  outcomeView,
  whenText,
  type OutcomeView,
} from "./restoreText";

interface Props {
  readonly folderId: FolderId;
  readonly tab: "versions" | "trash";
  readonly entryId?: string | undefined;
  readonly path?: string | undefined;
  readonly beforeDevice?: string | undefined;
  readonly onClose: () => void;
}

/** True below the width where timeline and tree fit side by side. */
function useNarrow(): boolean {
  const query = "(max-width: 760px)";
  const [narrow, setNarrow] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => {
      setNarrow(media.matches);
    };
    media.addEventListener("change", update);
    return () => {
      media.removeEventListener("change", update);
    };
  }, []);
  return narrow;
}

export function RestoreDialog({
  folderId,
  tab: initialTab,
  entryId,
  path,
  beforeDevice,
  onClose,
}: Props) {
  const t = useT();
  const snapshot = useSnapshot();
  const titleId = useId();
  const [tab, setTab] = useState(initialTab);
  const folderName = snapshot.folders.find((folder) => folder.id === folderId)?.name ?? "";
  const tabs = ["versions", "trash"] as const;
  const tabIds = { versions: useId(), trash: useId() };
  const panelId = useId();

  return (
    <Dialog labelledBy={titleId} size="large" onClose={onClose} closeOnOutside={false}>
      <div className="view-head">
        <h2 id={titleId} className="dialog-title">
          {tab === "versions"
            ? t("restore.title", { folder: folderName })
            : t("trash.title", { folder: folderName })}
        </h2>
        <div
          className="tabs"
          role="tablist"
          aria-label={t("restore.title", { folder: folderName })}
          onKeyDown={(event) => {
            if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
            event.preventDefault();
            const next = tab === "versions" ? "trash" : "versions";
            setTab(next);
            document.getElementById(tabIds[next])?.focus();
          }}
        >
          {tabs.map((name) => (
            <button
              key={name}
              id={tabIds[name]}
              type="button"
              role="tab"
              className="tab"
              aria-selected={tab === name}
              aria-controls={panelId}
              tabIndex={tab === name ? 0 : -1}
              onClick={() => {
                setTab(name);
              }}
            >
              {name === "versions" ? t("restore.tab.versions") : t("restore.tab.trash")}
            </button>
          ))}
        </div>
      </div>
      <div id={panelId} role="tabpanel" aria-labelledby={tabIds[tab]} className="view-body">
        {tab === "versions" ? (
          <VersionsTab
            folderId={folderId}
            folderName={folderName}
            initialEntry={entryId}
            initialPath={path}
            beforeDevice={beforeDevice}
          />
        ) : (
          <TrashTab folderId={folderId} />
        )}
      </div>
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

function VersionsTab({
  folderId,
  folderName,
  initialEntry,
  initialPath,
  beforeDevice,
}: {
  readonly folderId: FolderId;
  readonly folderName: string;
  readonly initialEntry: string | undefined;
  readonly initialPath: string | undefined;
  readonly beforeDevice: string | undefined;
}) {
  const t = useT();
  const backend = useBackend();
  const [path, setPath] = useState(initialPath);
  const [timeline] = useLoad(() => backend.getTimeline(folderId, path), [backend, folderId, path]);
  const [chosen, setChosen] = useState<string | null>(initialEntry ?? null);
  const [marker, setMarker] = useState<{ entryId: string; device: string } | null>(
    initialEntry && beforeDevice ? { entryId: initialEntry, device: beforeDevice } : null,
  );
  const [listOpen, setListOpen] = useState(false);
  const narrow = useNarrow();

  if (timeline.status === "loading") return <Loading />;
  if (timeline.status === "failed")
    return <Feedback tone="error">{errorText(timeline.error, t)}</Feedback>;
  const entries = timeline.data.entries;
  const selected = entries.find((entry) => entry.id === chosen) ?? entries[0];
  const fileName = path?.split("/").pop();

  return (
    <div className={narrow ? "restore-grid narrow" : "restore-grid"}>
      <div className="timeline-pane">
        {fileName && (
          <p className="filter-chip">
            <span>{t("restore.file.historyOf", { name: fileName })}</span>
            <button
              type="button"
              className="link-button inline"
              onClick={() => {
                setPath(undefined);
              }}
            >
              {t("restore.file.historyAll")}
            </button>
          </p>
        )}
        {entries.length === 0 ? (
          <p className="empty-line">{t("restore.none")}</p>
        ) : narrow && !listOpen && selected ? (
          <div className="timeline-folded">
            <EntryLabel entry={selected} marker={marker} full />
            <button
              type="button"
              className="button secondary small"
              onClick={() => {
                setListOpen(true);
              }}
            >
              {t("restore.otherVersion")}
            </button>
          </div>
        ) : (
          <TimelineList
            timeline={timeline.data}
            selectedId={selected?.id ?? null}
            marker={marker}
            onSelect={(id) => {
              setChosen(id);
            }}
            onPick={() => {
              if (narrow) setListOpen(false);
            }}
          />
        )}
        <BeforeDevice
          folderId={folderId}
          onFound={(entryId, device) => {
            setChosen(entryId);
            setMarker({ entryId, device });
            setListOpen(false);
          }}
        />
      </div>
      <div className="tree-pane">
        {selected ? (
          <VersionTreeView
            key={selected.id}
            folderId={folderId}
            folderName={folderName}
            entry={selected}
            beforeDevice={marker?.entryId === selected.id}
            onHistory={(filePath) => {
              setPath(filePath);
              setChosen(null);
            }}
          />
        ) : (
          <p className="empty-line">{t("restore.none")}</p>
        )}
      </div>
    </div>
  );
}

function EntryLabel({
  entry,
  marker,
  full = false,
}: {
  readonly entry: TimelineEntry;
  readonly marker: { entryId: string; device: string } | null;
  /** With the day ("today, 11:20"), when no day heading stands above it. */
  readonly full?: boolean;
}) {
  const t = useT();
  const language = useLanguage();
  const now = useNow();
  return (
    <span className="entry-label">
      <span className="entry-head">
        {full
          ? `${whenText(language, t, entry.at, now)}, ${entry.device}`
          : t("restore.entry", { time: formatTime(language, entry.at), device: entry.device })}
      </span>
      {marker?.entryId === entry.id && (
        <span className="entry-marker">
          {t("restore.beforeDeviceEntry", { device: marker.device })}
        </span>
      )}
      <span className="entry-sub">{entrySummary(entry, t)}</span>
    </span>
  );
}

function TimelineList({
  timeline,
  selectedId,
  marker,
  onSelect,
  onPick,
}: {
  readonly timeline: Timeline;
  readonly selectedId: string | null;
  readonly marker: { entryId: string; device: string } | null;
  readonly onSelect: (id: string) => void;
  readonly onPick: () => void;
}) {
  const t = useT();
  const language = useLanguage();
  const now = useNow();
  const listId = useId();
  const list = useRef<HTMLDivElement>(null);
  const entries = timeline.entries;
  const groups = useMemo(() => groupByDay(entries, now), [entries, now]);
  const index = entries.findIndex((entry) => entry.id === selectedId);
  const optionId = (id: string) => `${listId}-${id}`;

  useEffect(() => {
    if (selectedId)
      document.getElementById(optionId(selectedId))?.scrollIntoView({ block: "nearest" });
    // optionId is derived from listId
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  return (
    <div className="timeline">
      <div
        ref={list}
        className="timeline-list"
        role="listbox"
        tabIndex={0}
        aria-label={t("restore.list")}
        aria-activedescendant={selectedId ? optionId(selectedId) : undefined}
        onKeyDown={(event) => {
          const moves: Record<string, number> = {
            ArrowDown: index + 1,
            ArrowUp: index - 1,
            Home: 0,
            End: entries.length - 1,
          };
          const to = moves[event.key];
          if (event.key === "Enter") {
            event.preventDefault();
            onPick();
            return;
          }
          if (to === undefined) return;
          event.preventDefault();
          const next = entries[Math.max(0, Math.min(entries.length - 1, to))];
          if (next) onSelect(next.id);
        }}
      >
        {groups.map((group) => {
          const first = group[0];
          if (!first) return null;
          const headingId = `${listId}-day-${first.id}`;
          return (
            <div key={first.id} role="group" aria-labelledby={headingId} className="timeline-day">
              <div id={headingId} className="timeline-day-head" role="presentation">
                {dayHeading(language, t, first.at, now)}
              </div>
              {group.map((entry) => (
                <div
                  key={entry.id}
                  id={optionId(entry.id)}
                  role="option"
                  aria-selected={entry.id === selectedId}
                  className="timeline-option"
                  onClick={() => {
                    onSelect(entry.id);
                    onPick();
                    list.current?.focus();
                  }}
                >
                  <EntryLabel entry={entry} marker={marker} />
                  {entry.reanchored && (
                    <span className="entry-reanchor">{t("restore.reanchored")}</span>
                  )}
                </div>
              ))}
            </div>
          );
        })}
      </div>
      <div className="timeline-foot">
        {timeline.expiredCount > 0 && (
          <p className="muted">{t("restore.expiredOlder", { count: timeline.expiredCount })}</p>
        )}
        <p className="muted">{t("restore.retention", { days: timeline.retentionDays })}</p>
      </div>
    </div>
  );
}

function OutcomeLine({
  view,
  onUndo,
  onCancelJob,
}: {
  readonly view: OutcomeView;
  readonly onUndo: (token: string) => void;
  readonly onCancelJob: (jobId: string) => void;
}) {
  const t = useT();
  const { undoToken, jobId } = view;
  return (
    <Feedback
      tone={view.tone}
      action={
        undoToken ? (
          <button
            type="button"
            className="link-button inline"
            onClick={() => {
              onUndo(undoToken);
            }}
          >
            {t("common.undo")}
          </button>
        ) : jobId ? (
          <button
            type="button"
            className="link-button inline"
            onClick={() => {
              onCancelJob(jobId);
            }}
          >
            {t("common.cancel")}
          </button>
        ) : undefined
      }
    >
      {view.text}
    </Feedback>
  );
}

function useOutcome() {
  const backend = useBackend();
  const t = useT();
  const [view, setView] = useState<OutcomeView | null>(null);
  const action = useAction();
  const show = (outcome: RestoreOutcome, doneText: (count: number) => string) => {
    setView(outcomeView(outcome, t, doneText));
  };
  const line = view && (
    <OutcomeLine
      view={view}
      onUndo={(token) => {
        void action.run(async () => {
          await backend.undo(token);
          setView({ tone: "ok", text: t("common.undone"), undoToken: null, jobId: null });
        });
      }}
      onCancelJob={(jobId) => {
        void action.run(async () => {
          await backend.cancelRestore(jobId);
          setView(null);
        });
      }}
    />
  );
  return {
    show,
    line,
    clear: () => {
      setView(null);
    },
    action,
  };
}

function VersionTreeView({
  folderId,
  folderName,
  entry,
  beforeDevice,
  onHistory,
}: {
  readonly folderId: FolderId;
  readonly folderName: string;
  readonly entry: TimelineEntry;
  /** The state before a device's changes: resetting the folder is what the person came for. */
  readonly beforeDevice: boolean;
  readonly onHistory: (path: string) => void;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const now = useNow();
  const [tree] = useLoad(
    () => backend.getTreeAt(folderId, entry.id),
    [backend, folderId, entry.id],
  );
  const [onlyDiff, setOnlyDiff] = useState(true);
  const reset = useOutcome();
  const when = whenText(language, t, entry.at, now);
  const checkId = useId();
  const resetButton = useRef<HTMLButtonElement>(null);
  const treeReady = tree.status === "ready";
  // "Undo a device" (UX 8.9) leads here: the reset gets the focus once the state is shown, so
  // Enter leads on to the native question that names what changes.
  useEffect(() => {
    if (!beforeDevice || !treeReady) return;
    resetButton.current?.scrollIntoView({ block: "nearest" });
    resetButton.current?.focus();
  }, [beforeDevice, treeReady]);

  return (
    <div className="tree-view">
      <h3 className="tree-title">{t("restore.stateOf", { when })}</h3>
      {tree.status === "loading" && <Loading />}
      {tree.status === "failed" && <Feedback tone="error">{errorText(tree.error, t)}</Feedback>}
      {tree.status === "ready" && (
        <>
          <p className="tree-diff">{diffText(tree.data.changed, tree.data.missing, t)}</p>
          <label className="check" htmlFor={checkId}>
            <input
              id={checkId}
              type="checkbox"
              checked={onlyDiff}
              onChange={(event) => {
                setOnlyDiff(event.target.checked);
              }}
            />
            {t("restore.onlyDiff")}
          </label>
          <TreeList
            nodes={tree.data.nodes}
            onlyDiff={onlyDiff}
            folderId={folderId}
            entryId={entry.id}
            onHistory={onHistory}
          />
          <div className="tree-actions">
            <button
              ref={resetButton}
              type="button"
              className={beforeDevice ? "button primary" : "button secondary"}
              disabled={reset.action.pending}
              onClick={() => {
                reset.clear();
                // The shell asks natively, with the folder and the files that disappear on
                // every device (follow-up check N-1); "no" there changes nothing and says nothing.
                void reset.action.run(async () => {
                  const outcome = await backend.resetFolder(folderId, entry.id);
                  if (outcome !== null) {
                    reset.show(outcome, () =>
                      t("restore.folder.done", { folder: folderName, when }),
                    );
                  }
                });
              }}
            >
              {t("restore.folder")}
            </button>
            {reset.line}
          </div>
          {reset.action.error !== null && (
            <Feedback tone="error">{errorText(reset.action.error, t)}</Feedback>
          )}
        </>
      )}
    </div>
  );
}

function TreeList({
  nodes,
  onlyDiff,
  folderId,
  entryId,
  onHistory,
}: {
  readonly nodes: readonly TreeNode[];
  readonly onlyDiff: boolean;
  readonly folderId: FolderId;
  readonly entryId: string;
  readonly onHistory: (path: string) => void;
}) {
  const t = useT();
  const visible = onlyDiff ? withParents(nodes) : nodes;
  if (visible.length === 0) return <p className="empty-line">{t("restore.noDiff")}</p>;
  return (
    <ul className="tree-list">
      {visible.map((node) => (
        <TreeRow
          key={node.path}
          node={node}
          folderId={folderId}
          entryId={entryId}
          onHistory={onHistory}
        />
      ))}
    </ul>
  );
}

/** Only files that differ, with the folders on their way, so the tree stays readable. */
export function withParents(nodes: readonly TreeNode[]): TreeNode[] {
  const keep = new Set<string>();
  for (const node of nodes) {
    if (node.kind !== "file" || node.diff === "same") continue;
    keep.add(node.path);
    const parts = node.path.split("/");
    for (let i = 1; i < parts.length; i += 1) keep.add(parts.slice(0, i).join("/"));
  }
  return nodes.filter((node) => keep.has(node.path));
}

function TreeRow({
  node,
  folderId,
  entryId,
  onHistory,
}: {
  readonly node: TreeNode;
  readonly folderId: FolderId;
  readonly entryId: string;
  readonly onHistory: (path: string) => void;
}) {
  const t = useT();
  const backend = useBackend();
  const outcome = useOutcome();
  const [menuOpen, setMenuOpen] = useState(false);
  const diffLabel = {
    same: null,
    different: t("restore.file.different"),
    missing: t("restore.file.missing"),
    newer: t("restore.file.newer"),
  }[node.diff];
  const restorable = node.kind === "file" && (node.diff === "different" || node.diff === "missing");
  const restore = (mode: "replace" | "copy") => {
    void outcome.action.run(async () => {
      const result = await backend.restoreFile(folderId, entryId, node.path, mode);
      outcome.show(result, () =>
        mode === "copy" ? t("restore.file.copied", { name: node.name }) : t("restore.file.done"),
      );
    });
  };

  return (
    <li
      className={`tree-row diff-${node.diff}`}
      style={{ paddingInlineStart: `${String(node.depth * 20 + 4)}px` }}
    >
      <div className="tree-line">
        <span className="row-icon small">
          {node.kind === "dir" ? <FolderIcon size={18} /> : <FileIcon size={18} />}
        </span>
        <span className="tree-name">{displayName(node.name)}</span>
        {diffLabel && <span className="tree-diff-label">{diffLabel}</span>}
        {restorable && (
          <>
            <button
              type="button"
              className="button secondary small"
              disabled={outcome.action.pending}
              onClick={() => {
                restore("replace");
              }}
            >
              {t("restore.file.restore")}
            </button>
            <RowMenu
              items={[
                {
                  id: "copy",
                  label: t("restore.file.copy"),
                  onSelect: () => {
                    restore("copy");
                  },
                },
                {
                  id: "history",
                  label: t("restore.file.history"),
                  onSelect: () => {
                    onHistory(node.path);
                  },
                },
              ]}
              label={t("main.rowMenu", { name: node.name })}
              open={menuOpen}
              onOpenChange={setMenuOpen}
            />
          </>
        )}
      </div>
      {outcome.line}
      {outcome.action.error !== null && (
        <Feedback tone="error">{errorText(outcome.action.error, t)}</Feedback>
      )}
    </li>
  );
}

/** "State before changes from ..." (UX 9.4, manual path): device and start date. */
function BeforeDevice({
  folderId,
  onFound,
}: {
  readonly folderId: FolderId;
  readonly onFound: (entryId: string, device: string) => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [open, setOpen] = useState(false);
  const [devices] = useLoad(
    () => (open ? backend.listDevices() : Promise.resolve(null)),
    [backend, open],
  );
  const [deviceId, setDeviceId] = useState("");
  const [from, setFrom] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const action = useAction();
  const deviceField = useId();
  const fromField = useId();

  if (!open) {
    return (
      <button
        type="button"
        className="link-button before-device-toggle"
        onClick={() => {
          setOpen(true);
        }}
      >
        {t("restore.beforeDevice")}
      </button>
    );
  }
  const list =
    devices.status === "ready" && devices.data
      ? devices.data.devices.filter((device) => !device.isThis)
      : [];
  const chosenId = deviceId || list[0]?.id || "";
  return (
    <form
      className="before-device"
      onSubmit={(event) => {
        event.preventDefault();
        const device = list.find((item) => item.id === chosenId);
        if (!device) return;
        const start = from ? new Date(`${from}T00:00:00`).getTime() : 0;
        void action.run(async () => {
          const entryId = await backend.findBeforeDevice(folderId, device.id, start);
          if (entryId) {
            setMessage(null);
            onFound(entryId, device.name);
          } else {
            setMessage(t("restore.beforeDevice.none"));
          }
        });
      }}
    >
      <p className="muted">{t("restore.beforeDevice.advice")}</p>
      {devices.status === "loading" && <Loading />}
      {devices.status === "failed" && (
        <Feedback tone="error">{errorText(devices.error, t)}</Feedback>
      )}
      <div className="field-grid" hidden={devices.status !== "ready"}>
        <label htmlFor={deviceField} className="field-label">
          {t("restore.beforeDevice.device")}
        </label>
        <select
          id={deviceField}
          className="select"
          value={chosenId}
          onChange={(event) => {
            setDeviceId(event.target.value);
          }}
        >
          {list.map((device) => (
            <option key={device.id} value={device.id}>
              {device.name}
            </option>
          ))}
        </select>
        <label htmlFor={fromField} className="field-label">
          {t("restore.beforeDevice.from")}
        </label>
        <input
          id={fromField}
          className="input"
          type="date"
          value={from}
          onChange={(event) => {
            setFrom(event.target.value);
          }}
        />
      </div>
      <div className="group-actions">
        <button
          type="submit"
          className="button secondary small"
          disabled={list.length === 0}
          aria-disabled={action.pending || undefined}
          aria-busy={action.pending || undefined}
        >
          {action.pending ? t("restore.beforeDevice.finding") : t("restore.beforeDevice.find")}
        </button>
      </div>
      {message && <Feedback tone="info">{message}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
    </form>
  );
}

function TrashTab({ folderId }: { readonly folderId: FolderId }) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const now = useNow();
  const days = useSnapshot().account?.retentionDays ?? 30;
  const [items, reload] = useLoad(() => backend.getTrash(folderId), [backend, folderId]);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [anchor, setAnchor] = useState<string | null>(null);
  const outcome = useOutcome();
  const searchId = useId();

  const restore = (ids: readonly string[]) => {
    void outcome.action.run(async () => {
      const result = await backend.restoreTrash(folderId, ids);
      outcome.show(result, (count) => t("trash.restored", { count }));
      if (result.kind === "done") {
        setSelected(new Set());
        reload();
      }
    });
  };

  if (items.status === "loading") return <Loading />;
  if (items.status === "failed")
    return <Feedback tone="error">{errorText(items.error, t)}</Feedback>;
  const needle = query.trim().toLowerCase();
  const visible = items.data.filter((item) => item.name.toLowerCase().includes(needle));
  const toggle = (id: string, event: { shiftKey: boolean }) => {
    const next = new Set(selected);
    if (event.shiftKey && anchor) {
      const ids = visible.map((item) => item.id);
      const from = ids.indexOf(anchor);
      const to = ids.indexOf(id);
      for (const rangeId of ids.slice(Math.min(from, to), Math.max(from, to) + 1))
        next.add(rangeId);
    } else if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setAnchor(id);
    setSelected(next);
  };

  return (
    <div className="trash">
      <div className="search">
        <SearchIcon size={18} />
        <label htmlFor={searchId} className="sr-only">
          {t("trash.search")}
        </label>
        <input
          id={searchId}
          className="input search-input"
          type="search"
          placeholder={t("trash.search")}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
          }}
        />
      </div>
      {items.data.length === 0 ? (
        <p className="empty-line">{t("trash.empty")}</p>
      ) : visible.length === 0 ? (
        <p className="empty-line">{t("trash.noMatch", { query })}</p>
      ) : (
        <ul className="trash-list">
          {visible.map((item) => (
            <li
              key={item.id}
              className={selected.has(item.id) ? "trash-row selected" : "trash-row"}
            >
              <input
                type="checkbox"
                className="trash-check"
                checked={selected.has(item.id)}
                aria-label={t("trash.select", { name: item.name })}
                onClick={(event) => {
                  event.preventDefault();
                  toggle(item.id, event);
                }}
                onKeyDown={(event) => {
                  if (event.key === " ") {
                    event.preventDefault();
                    toggle(item.id, event);
                  }
                }}
                readOnly
              />
              <span className="trash-text">
                <span className="trash-name">{displayName(item.name)}</span>
                <span className="trash-sub">
                  {item.dir ? `${displayName(item.dir).replaceAll("/", "\\")}\\ ` : ""}
                  {t("trash.deleted", {
                    when: formatRelative(language, item.deletedAt, now),
                    device: item.device,
                  })}
                </span>
              </span>
              <button
                type="button"
                className="button secondary small"
                disabled={outcome.action.pending}
                onClick={() => {
                  restore([item.id]);
                }}
              >
                {t("trash.restore")}
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="trash-foot">
        {selected.size > 1 && (
          <button
            type="button"
            className="button primary"
            disabled={outcome.action.pending}
            onClick={() => {
              restore([...selected]);
            }}
          >
            {t("trash.restoreSelected", { count: selected.size })}
          </button>
        )}
        {outcome.line}
        {outcome.action.error !== null && (
          <Feedback tone="error">{errorText(outcome.action.error, t)}</Feedback>
        )}
        <p className="muted">{t("trash.info", { days })}</p>
      </div>
    </div>
  );
}
