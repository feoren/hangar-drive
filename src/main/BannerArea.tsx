// The banner area (UX 6.3): at most one banner, the most urgent; the others are counted on it
// and can be stepped through. Banners are the only place where problems appear in the window.

import { useEffect, useRef, useState, type RefObject } from "react";

import type { FocusRequest, HeadsRequest } from "../App";
import { formatSince, formatSize } from "../format";
import { shownWarnings, tone, type ShownWarning } from "../domain/warnings";
import { useLanguage, useT, type Translate } from "../i18n";
import { errorCode } from "../backend/errors";
import type { Backend } from "../backend/types";
import { headsBody } from "../problems/RemovedHeadsDialog";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { Feedback } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import type { Open } from "./openDialog";

interface BannerButton {
  readonly label: string;
  /** Opens a dialog, or runs a backend call whose result line `done` describes. */
  readonly onClick: () => Promise<string | null> | undefined;
  readonly primary?: boolean;
}

interface BannerContent {
  readonly title: string | null;
  /** Null where the title says it all (the quiet two-versions banner, UX 7.1). */
  readonly body: string | null;
  readonly buttons: readonly BannerButton[];
}

/**
 * Whether this build can update itself: unknown until `getAbout` answered, "off" without an
 * updater key (then "Update now" is hidden instead of failing).
 */
export type UpdatesState = "unknown" | "on" | "off";

function content(
  warning: ShownWarning,
  t: Translate,
  backend: Backend,
  open: Open,
  since: (ms: number) => string,
  size: (bytes: number) => string,
  updates: { readonly state: UpdatesState; readonly turnedOff: () => void },
): BannerContent {
  const app = t("app.name");
  const copyReport: BannerButton = {
    label: t("common.copyReport"),
    onClick: async () => {
      await backend.copyErrorReport();
      return t("common.reportCopied");
    },
  };
  switch (warning.kind) {
    case "suspect":
      return {
        title: t("suspect.title", { device: warning.deviceName }),
        body: t("suspect.body", { days: warning.days }),
        buttons: [
          {
            label: t("suspect.what"),
            primary: true,
            onClick: () => {
              open({ kind: "suspect", warning });
            },
          },
          {
            label: t("suspect.me"),
            onClick: async () => {
              await backend.dismissSuspect(warning.id);
              return t("suspect.meDone");
            },
          },
        ],
      };
    case "massDelete":
      return {
        title: t("deletes.title", { count: warning.count }),
        body: t("deletes.body", { count: warning.count, folder: warning.folderName }),
        buttons: [
          {
            label: t("deletes.decide"),
            primary: true,
            onClick: () => {
              open({ kind: "massDelete", warning });
            },
          },
        ],
      };
    case "removedHeads":
      return {
        title: t("heads.title"),
        body: headsBody(warning, t),
        buttons: [
          {
            label: t("deletes.decide"),
            primary: true,
            onClick: () => {
              open({ kind: "removedHeads", warning });
            },
          },
        ],
      };
    case "removed":
      return {
        title: null,
        // The server's `deviceRemoved` at sign-in does not say who removed this device.
        body:
          warning.by === "" ? t("removed.bodyUnknown") : t("removed.body", { device: warning.by }),
        buttons: [
          {
            label: t("removed.repair"),
            primary: true,
            onClick: () => {
              open({ kind: "repair" });
            },
          },
          {
            label: t("removed.notMe"),
            onClick: () => {
              open({ kind: "notMe" });
            },
          },
        ],
      };
    // The server says this device was removed, which the device cannot check (security review
    // H2); the shell asks natively before it forgets the account here.
    case "removalReported":
      return {
        title: null,
        body: t("removalReported.body", { app }),
        buttons: [
          {
            label: t("removalReported.confirm"),
            primary: true,
            onClick: async () => {
              await backend.confirmDeviceRemoved();
              return null;
            },
          },
          copyReport,
        ],
      };
    // The server's newest version of a folder is beyond a folder's limits (security review M3):
    // an earlier version replaces it.
    case "treeLimit":
      return {
        title: t("treeLimit.title", { folder: warning.folderName }),
        body: t("treeLimit.body", { app }),
        buttons: [
          {
            label: t("folder.menu.versions"),
            primary: true,
            onClick: () => {
              open({ kind: "restore", folderId: warning.folderId, tab: "versions" });
            },
          },
        ],
      };
    case "refused":
      return {
        title: null,
        body: t("refused.body"),
        buttons: [
          {
            label: t("removed.repair"),
            primary: true,
            onClick: () => {
              open({ kind: "repair" });
            },
          },
          copyReport,
        ],
      };
    case "updateRequired":
      if (updates.state !== "on") {
        return {
          title: null,
          body:
            updates.state === "off" ? t("update.bodyManual", { app }) : t("update.body", { app }),
          buttons: [],
        };
      }
      return {
        title: null,
        body: t("update.body", { app }),
        buttons: [
          {
            label: t("update.now"),
            primary: true,
            onClick: async () => {
              try {
                const outcome = await backend.installUpdate();
                // "No" in the native question installs nothing and says nothing.
                if (outcome.kind === "declined") return null;
                return outcome.kind === "upToDate"
                  ? t("update.upToDate")
                  : t("update.installed", { version: outcome.version, app });
              } catch (error) {
                // A build without an updater key: no error, the button just goes away.
                if (errorCode(error) !== "updatesOff") throw error;
                updates.turnedOff();
                return null;
              }
            },
          },
        ],
      };
    case "serverIdentity": {
      const compare: BannerButton = {
        label: t("server.fix.compare"),
        primary: !warning.hasOtherDevice,
        onClick: () => {
          open({ kind: "serverCompare" });
        },
      };
      return {
        title: null,
        body: t("server.identity", { app }),
        buttons: warning.hasOtherDevice
          ? [
              {
                label: t("server.fix.scan"),
                primary: true,
                onClick: () => {
                  open({ kind: "serverScan" });
                },
              },
              compare,
            ]
          : [compare],
      };
    }
    case "olderState":
      return {
        title: t("older.title", { folder: warning.folderName }),
        body: `${t("older.body")} ${t("older.localOk")}`,
        buttons: [
          {
            label: t("older.resume"),
            primary: true,
            onClick: () => {
              open({
                kind: "reanchor",
                folderId: warning.folderId,
                folderName: warning.folderName,
              });
            },
          },
          {
            label: t("older.check"),
            onClick: async () => {
              const result = await backend.checkOlderState(warning.folderId);
              return result === "stillOlder" ? t("older.stillOlder") : null;
            },
          },
        ],
      };
    case "missingFolder":
      return {
        title: t("missing.title", { folder: warning.folderName }),
        body: t("missing.body", { app }),
        buttons: [
          {
            label: t("missing.find"),
            primary: true,
            onClick: async () => {
              const result = await backend.findMissingFolder(warning.folderId);
              if (result.kind !== "refused") return null;
              return result.reason === "wrongFolder"
                ? t("missing.wrongFolder", { folder: warning.folderName })
                : folderRefusalText(result.reason, result.folder, t);
            },
          },
          {
            label: t("missing.redownload"),
            onClick: async () => {
              await backend.redownloadFolder(warning.folderId);
              return null;
            },
          },
        ],
      };
    case "quotaFull":
      return { title: t("quotaFull.title"), body: t("quotaFull.body"), buttons: [copyReport] };
    case "quota":
      return { title: t("quota.title"), body: t("quota.body"), buttons: [] };
    case "serverDisk":
      return { title: t("serverDisk.title"), body: t("serverDisk.body"), buttons: [copyReport] };
    case "diskFull":
      return {
        title: t("disk.title"),
        body: t("disk.body", { app, size: size(warning.needed) }),
        buttons: [
          {
            label: t("disk.open"),
            primary: true,
            onClick: async () => {
              await backend.openStorageSettings();
              return null;
            },
          },
        ],
      };
    case "serverLong":
      return {
        title: null,
        body: t("offline.serverLong", { since: since(warning.since) }),
        buttons: [
          copyReport,
          {
            label: t("common.retry"),
            onClick: async () => {
              await backend.retryConnection();
              return null;
            },
          },
        ],
      };
    case "conflicts":
      return {
        title: t("conflict.banner", { count: warning.count }),
        body: null,
        buttons: [
          {
            label: t("conflict.view"),
            onClick: () => {
              open({ kind: "conflicts" });
            },
          },
        ],
      };
    case "names":
      return {
        title: t("names.banner", { count: warning.count }),
        body: t("names.ignoreHelp"),
        buttons: [
          {
            label: t("conflict.view"),
            onClick: () => {
              open({ kind: "names" });
            },
          },
        ],
      };
  }
}

export function folderRefusalText(
  reason: "network" | "root" | "system" | "nested" | "noAccess" | "wrongFolder",
  folder: string | null,
  t: Translate,
): string {
  const app = t("app.name");
  switch (reason) {
    case "network":
      return t("error.folder.network");
    case "root":
      return t("error.folder.root");
    case "system":
      return t("error.folder.system");
    case "nested":
      return t("error.folder.nested", { folder: folder ?? "" });
    case "noAccess":
      return t("error.folder.noAccess", { app });
    case "wrongFolder":
      return t("missing.wrongFolder", { folder: folder ?? "" });
  }
}

export function BannerArea({
  open,
  focus,
  heads,
  region,
}: {
  readonly open: Open;
  readonly focus: FocusRequest;
  /** The last `removedHeads` event: its question comes to the front once the warning is there. */
  readonly heads: HeadsRequest | null;
  /** The banner element, so the window can put the focus back on it. */
  readonly region: RefObject<HTMLDivElement | null>;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const now = useNow();
  const warnings = shownWarnings(snapshot, now);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ id: string; text: string } | null>(null);
  const action = useAction();
  const autoOpened = useRef(new Set<string>());
  const handledHeads = useRef(0);
  // Only a needed update asks whether this build can update itself.
  const needsUpdate = warnings.some((item) => item.kind === "updateRequired");
  const [about] = useLoad(
    () => (needsUpdate ? backend.getAbout() : Promise.resolve(null)),
    [backend, needsUpdate],
  );
  const [refusedUpdate, setRefusedUpdate] = useState(false);
  const updates: UpdatesState = refusedUpdate
    ? "off"
    : about.status === "loading"
      ? "unknown"
      : about.status === "ready" && about.data?.updates === false
        ? "off"
        : "on";

  const index = Math.max(
    0,
    warnings.findIndex((warning) => warning.id === currentId),
  );
  const warning = warnings[index];

  // A notification click or "Show problem" in the tray brings its banner forward and focuses it.
  const [handledFocus, setHandledFocus] = useState(0);
  if (focus.at !== handledFocus) {
    setHandledFocus(focus.at);
    if (focus.warningId) setCurrentId(focus.warningId);
    else setCurrentId(null);
  }
  useEffect(() => {
    if (focus.at > 0) region.current?.focus();
  }, [focus.at, region]);

  // Many deletions and changes of a removed device need a decision, so they also open their
  // dialog once (UX 8.1, 8.9); a new `removedHeads` event opens its question again.
  useEffect(() => {
    if (heads && heads.at !== handledHeads.current) {
      const item = warnings.find(
        (warning) => warning.kind === "removedHeads" && warning.folderId === heads.folderId,
      );
      if (item?.kind === "removedHeads") {
        handledHeads.current = heads.at;
        autoOpened.current.add(item.id);
        open({ kind: "removedHeads", warning: item, auto: true });
        return;
      }
    }
    for (const item of warnings) {
      if (autoOpened.current.has(item.id)) continue;
      if (item.kind === "massDelete") {
        autoOpened.current.add(item.id);
        open({ kind: "massDelete", warning: item, auto: true });
        break;
      }
      if (item.kind === "removedHeads") {
        autoOpened.current.add(item.id);
        open({ kind: "removedHeads", warning: item, auto: true });
        break;
      }
    }
  }, [warnings, open, heads]);

  if (!warning) {
    return feedback ? (
      <div className="banner-after">
        <Feedback>{feedback.text}</Feedback>
      </div>
    ) : null;
  }

  const view = content(
    warning,
    t,
    backend,
    open,
    (ms) => formatSince(language, ms, now),
    (bytes) => formatSize(language, bytes),
    {
      state: updates,
      turnedOff: () => {
        setRefusedUpdate(true);
      },
    },
  );
  const others = warnings.length - 1;
  const kind = tone(warning);
  const titleId = `banner-${warning.id}`;
  const next = warnings[(index + 1) % warnings.length];

  return (
    <div
      ref={region}
      key={warning.id}
      className={`banner banner-${kind}`}
      role={kind === "info" ? "status" : "alert"}
      aria-labelledby={view.title ? titleId : undefined}
      tabIndex={-1}
    >
      <div className="banner-text">
        {view.title && (
          <h2 id={titleId} className="banner-title">
            {view.title}
          </h2>
        )}
        {view.body !== null && <p className="banner-body">{view.body}</p>}
        {feedback &&
          (feedback.id === warning.id || !warnings.some((item) => item.id === feedback.id)) && (
            <Feedback>{feedback.text}</Feedback>
          )}
        {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      </div>
      {(view.buttons.length > 0 || others > 0) && (
        <div className="banner-actions">
          {view.buttons.map((button) => (
            <button
              key={button.label}
              type="button"
              className={button.primary ? "button primary small" : "button secondary small"}
              disabled={action.pending}
              onClick={() => {
                const result = button.onClick();
                if (result instanceof Promise) {
                  void action.run(async () => {
                    const text = await result;
                    setFeedback(text ? { id: warning.id, text } : null);
                  });
                } else {
                  setFeedback(null);
                }
              }}
            >
              {button.label}
            </button>
          ))}
          {others > 0 && next && (
            <button
              type="button"
              className="link-button banner-more"
              onClick={() => {
                setFeedback(null);
                setCurrentId(next.id);
              }}
            >
              {t("main.moreNotices", { count: others })}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
