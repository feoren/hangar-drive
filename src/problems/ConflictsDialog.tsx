// Files in two versions (UX 7.1): nothing to decide, both versions are already there. Tidying up
// is optional: "Keep both" is the default and ends the entry; "Keep this one" puts the chosen
// content under the original name, with undo.

import { useId, useState } from "react";

import type { ConflictGroup } from "../backend/types";
import { formatRelative, formatSize } from "../format";
import { useLanguage, useT } from "../i18n";
import { useBackend, useNow, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

export function ConflictsDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const [loaded, reload] = useLoad(() => backend.listConflicts(), [backend]);
  const [feedback, setFeedback] = useState<{ text: string; undo: string | null } | null>(null);
  const action = useAction();

  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("conflict.title")}
      </h2>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {feedback && (
        <Feedback
          action={
            feedback.undo && (
              <button
                type="button"
                className="link-button inline"
                onClick={() => {
                  const token = feedback.undo;
                  if (!token) return;
                  void action.run(async () => {
                    await backend.undo(token);
                    setFeedback({ text: t("common.undone"), undo: null });
                    reload();
                  });
                }}
              >
                {t("common.undo")}
              </button>
            )
          }
        >
          {feedback.text}
        </Feedback>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      {loaded.status === "ready" &&
        (loaded.data.length === 0 ? (
          <p className="empty-line">{t("conflict.allDone")}</p>
        ) : (
          <div className="group-list">
            {loaded.data.map((group, index) => (
              <ConflictCard
                key={group.id}
                group={group}
                first={index === 0}
                onDone={(text, undo) => {
                  setFeedback({ text, undo });
                  reload();
                }}
              />
            ))}
          </div>
        ))}
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

function ConflictCard({
  group,
  first,
  onDone,
}: {
  readonly group: ConflictGroup;
  readonly first: boolean;
  readonly onDone: (text: string, undo: string | null) => void;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const now = useNow();
  const days = useSnapshot().account?.retentionDays ?? 30;
  const action = useAction();
  const original = group.versions.find((version) => version.original) ?? group.versions[0];
  const headingId = useId();

  return (
    <section className="group-card" aria-labelledby={headingId}>
      <h3 id={headingId} className="group-title">
        <span className="bidi-name">{original?.name}</span>
        {group.path && <span className="group-path"> {group.path}</span>}
      </h3>
      {group.kind === "caseOnly" && <p className="muted">{t("conflict.caseOnly")}</p>}
      <ul className="version-list">
        {group.versions.map((version) => (
          <li key={version.id} className="version-row">
            <span className="version-text">
              <span className="version-name">{version.name}</span>
              <span className="version-sub">
                {t("conflict.version", {
                  device: version.device,
                  time: formatRelative(language, version.modified, now),
                })}
                , {formatSize(language, version.size)}
              </span>
            </span>
            <button
              type="button"
              className="button secondary small"
              disabled={action.pending}
              onClick={() => {
                void action.run(async () => {
                  const { undoToken } = await backend.keepConflictVersion(group.id, version.id);
                  onDone(t("conflict.keptThis", { days }), undoToken);
                });
              }}
            >
              {t("conflict.keepThis")}
            </button>
          </li>
        ))}
      </ul>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="group-actions">
        <button
          type="button"
          className="button secondary small"
          disabled={action.pending}
          onClick={() => {
            void action.run(() => backend.openConflict(group.id));
          }}
        >
          {t("conflict.openBoth")}
        </button>
        <button
          type="button"
          className="button primary small"
          data-autofocus={first ? true : undefined}
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              await backend.keepBothConflict(group.id);
              onDone(t("conflict.keptBoth"), null);
            });
          }}
        >
          {t("conflict.keepBoth")}
        </button>
      </div>
    </section>
  );
}
