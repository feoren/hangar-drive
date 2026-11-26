// The status at the top of the main window (UX 6.3): the tray's state sentence, large, with one
// muted line below. Screen readers hear only changes of the state itself, never the per-file
// counts (UX 12), through a separate live region.

import { useState } from "react";

import { formatSize, formatTime } from "../format";
import { useLanguage, useT } from "../i18n";
import { stateText, waitingLines, type TrayState } from "../tray/trayModel";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { useTrayState } from "../ui/appContext";
import { Feedback } from "../ui/parts";
import { StatusMark } from "../ui/StatusMark";
import { errorText, useAction } from "../ui/useAsync";

function markTone(state: TrayState, danger: boolean): string {
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

export function StatusHeader({ danger }: { readonly danger: boolean }) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const state = useTrayState();
  const now = useNow();
  const action = useAction();
  const sentence = stateText(state, t, language, now);

  // The live region keeps the sentence from the moment the state kind changed.
  const [announced, setAnnounced] = useState({ kind: state.kind, text: sentence });
  if (announced.kind !== state.kind) setAnnounced({ kind: state.kind, text: sentence });

  const { sync } = snapshot;
  const lines: string[] = [];
  let button: { label: string; run: () => Promise<void> } | null = null;
  switch (state.kind) {
    case "syncing":
      if (sync.bytesLeft > 0) {
        lines.push(t("main.status.remaining", { size: formatSize(language, sync.bytesLeft) }));
      }
      break;
    case "paused":
      button = { label: t("tray.resume"), run: () => backend.resume() };
      break;
    case "offline":
      if (state.reason === "noNetwork") {
        lines.push(t("offline.noNetwork"));
      } else {
        lines.push(t("offline.server", { app: t("app.name") }));
        button = { label: t("common.retry"), run: () => backend.retryConnection() };
      }
      break;
    case "attention":
      lines.push(t("main.status.attention"));
      break;
    case "upToDate":
      lines.push(...waitingLines(snapshot, t));
      if (sync.waitingMetered > 0) {
        button = { label: t("tray.syncNow"), run: () => backend.syncNow() };
      }
      if (lines.length === 0 && sync.lastSync !== null) {
        lines.push(t("main.status.lastSync", { time: formatTime(language, sync.lastSync) }));
      }
      break;
    case "setup":
      break;
  }

  const statusButton = button;
  return (
    <section className="status" aria-labelledby="status-title">
      <StatusMark
        icon={state.kind}
        size={48}
        className={`status-mark ${markTone(state, danger)}`}
      />
      <div className="status-text">
        <h1 id="status-title" className="status-title">
          {sentence}
        </h1>
        {lines.map((line) => (
          <p key={line} className="status-line">
            {line}
          </p>
        ))}
        {statusButton && (
          <div className="status-actions">
            <button
              type="button"
              className="button secondary small"
              disabled={action.pending}
              onClick={() => {
                void action.run(statusButton.run);
              }}
            >
              {statusButton.label}
            </button>
          </div>
        )}
        {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      </div>
      <p className="sr-only" role="status">
        {announced.text}
      </p>
    </section>
  );
}
