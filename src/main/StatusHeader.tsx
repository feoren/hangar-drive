// The status of the main window (UX 6.3): the tray's state as a compact item in the header, its
// mark and a short word, with the sentence and the quiet lines as tooltip and in a small panel
// that the item opens (with the action of the state, such as "Fortsetzen"). Screen readers get the
// sentence as the page heading and hear only changes of the state itself, never the per-file
// counts (UX 12), through a separate live region.

import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";

import { formatSize, formatTime } from "../format";
import { useLanguage, useT } from "../i18n";
import { stateText, waitingLines, type TrayState } from "../tray/trayModel";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { useTrayState } from "../ui/appContext";
import { Feedback } from "../ui/parts";
import { StatusMark } from "../ui/StatusMark";
import { errorText, useAction } from "../ui/useAsync";

export function markTone(state: TrayState, danger: boolean): string {
  switch (state.kind) {
    case "attention":
      return danger ? "tone-danger" : "tone-attention";
    case "syncing":
      return "tone-active";
    case "upToDate":
      return "tone-ok";
    default:
      return "tone-quiet";
  }
}

interface StatusAction {
  readonly label: string;
  readonly run: () => Promise<void>;
}

/** Everything the status says: the sentence, a short form for the header, lines, one action. */
function useStatus() {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const state = useTrayState();
  const now = useNow();
  const sentence = stateText(state, t, language, now);
  // Only the offline sentence is long; its short form is the one word.
  const short = state.kind === "offline" ? t("main.status.offline") : sentence;

  const { sync } = snapshot;
  const lines: string[] = [];
  let action: StatusAction | null = null;
  switch (state.kind) {
    case "syncing":
      if (sync.bytesLeft > 0) {
        lines.push(t("main.status.remaining", { size: formatSize(language, sync.bytesLeft) }));
      }
      break;
    case "paused":
      action = { label: t("tray.resume"), run: () => backend.resume() };
      break;
    case "offline":
      if (state.reason === "noNetwork") {
        lines.push(t("offline.noNetwork"));
      } else {
        lines.push(t("offline.server", { app: t("app.name") }));
        action = { label: t("common.retry"), run: () => backend.retryConnection() };
      }
      break;
    case "attention":
      lines.push(t("main.status.attention"));
      break;
    case "upToDate":
      lines.push(...waitingLines(snapshot, t));
      if (sync.waitingMetered > 0) {
        action = { label: t("tray.syncNow"), run: () => backend.syncNow() };
      }
      if (lines.length === 0 && sync.lastSync !== null) {
        lines.push(t("main.status.lastSync", { time: formatTime(language, sync.lastSync) }));
      }
      break;
    case "setup":
      break;
  }
  return { state, sentence, short, lines, action };
}

/** The sentence as the page's heading and the live region, at the start of the content. */
export function StatusHeading() {
  const { state, sentence } = useStatus();
  // The live region keeps the sentence from the moment the state kind changed.
  const [announced, setAnnounced] = useState({ kind: state.kind, text: sentence });
  if (announced.kind !== state.kind) setAnnounced({ kind: state.kind, text: sentence });
  return (
    <>
      <h1 className="sr-only">{sentence}</h1>
      <p className="sr-only" role="status">
        {announced.text}
      </p>
    </>
  );
}

/** The compact status in the header; it opens a small panel with the details and the action. */
export function StatusHeader({ danger }: { readonly danger: boolean }) {
  const t = useT();
  const { state, sentence, short, lines, action } = useStatus();
  const run = useAction();
  const [open, setOpen] = useState(false);
  const button = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const linesId = useId();

  useLayoutEffect(() => {
    if (open) panel.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (panel.current?.contains(target) || button.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => {
      document.removeEventListener("mousedown", close);
    };
  }, [open]);

  const closeAndFocus = () => {
    setOpen(false);
    button.current?.focus();
  };

  const statusAction = action;
  return (
    <div className="status">
      <button
        ref={button}
        type="button"
        className="quiet-button status-button"
        aria-label={sentence}
        aria-describedby={lines.length > 0 ? linesId : undefined}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        title={[sentence, ...lines].join("\n")}
        onClick={() => {
          setOpen(!open);
        }}
      >
        <StatusMark
          icon={state.kind}
          size={22}
          className={`status-mark ${markTone(state, danger)}`}
        />
        <span className="status-short">{short}</span>
      </button>
      <span id={linesId} className="sr-only">
        {lines.join(" ")}
      </span>
      {open && (
        <div
          ref={panel}
          id={panelId}
          className="status-panel"
          role="group"
          aria-label={sentence}
          tabIndex={-1}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              event.stopPropagation();
              closeAndFocus();
            }
          }}
        >
          <p className="status-title">{sentence}</p>
          {lines.map((line) => (
            <p key={line} className="status-line">
              {line}
            </p>
          ))}
          {statusAction && (
            <div className="status-actions">
              <button
                type="button"
                className="button secondary small"
                disabled={run.pending}
                onClick={() => {
                  void run.run(statusAction.run);
                }}
              >
                {statusAction.label}
              </button>
            </div>
          )}
          {run.error !== null && <Feedback tone="error">{errorText(run.error, t)}</Feedback>}
        </div>
      )}
    </div>
  );
}
