// Names that do not work on Windows (UX 7.2): the name, the reason in words, the device it came
// from. "Rename" starts with a suggestion and checks while typing; "Ignore" hides the entry here.

import { useId, useState } from "react";

import type { NameIssue, NameReason } from "../backend/types";
import { suggestWindowsName, windowsNameProblem } from "../domain/windowsNames";
import { useT, type Translate } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

export function reasonText(reason: NameReason, t: Translate): string {
  switch (reason.kind) {
    case "char":
      return t("names.char", { char: reason.char });
    case "reserved":
      return t("names.reserved", { name: reason.name });
    case "trailing":
      return t("names.trailing");
    case "control":
      return t("names.control");
    case "cannotCreate":
      return t("names.cannotCreate");
  }
}

export function NamesDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const [loaded, reload] = useLoad(() => backend.listNameIssues(), [backend]);
  const [feedback, setFeedback] = useState<string | null>(null);
  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose} closeOnOutside={false}>
      <h2 id={titleId} className="dialog-title">
        {t("names.title")}
      </h2>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {feedback && <Feedback>{feedback}</Feedback>}
      {loaded.status === "ready" &&
        (loaded.data.length === 0 ? (
          <p className="empty-line">{t("conflict.allDone")}</p>
        ) : (
          <div className="group-list">
            {loaded.data.map((issue) => (
              <NameCard
                key={issue.id}
                issue={issue}
                onDone={(text) => {
                  setFeedback(text);
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

function NameCard({
  issue,
  onDone,
}: {
  readonly issue: NameIssue;
  readonly onDone: (text: string | null) => void;
}) {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const fieldId = useId();
  const helpId = useId();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(() => suggestWindowsName(issue.name));
  const [serverError, setServerError] = useState<string | null>(null);
  const canRename = issue.reason.kind !== "cannotCreate";
  const live =
    name.trim() === ""
      ? t("error.rename.empty")
      : windowsNameProblem(name)
        ? t("error.rename.invalid")
        : null;
  const message = live ?? serverError;
  const where = [issue.folderName, issue.dir].filter(Boolean).join(" \\ ");

  return (
    <section className="group-card" aria-label={issue.name}>
      <h3 className="group-title">
        <span className="bidi-name">{issue.name}</span>
        <span className="group-path"> {where}</span>
      </h3>
      <p className="group-text">{reasonText(issue.reason, t)}</p>
      <p className="muted">{t("names.from", { device: issue.device })}</p>
      {editing ? (
        <form
          className="rename-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (live) return;
            void action.run(async () => {
              const result = await backend.renameNameIssue(issue.id, name.trim());
              if (result.ok) {
                onDone(t("names.renamed", { name: name.trim() }));
              } else {
                setServerError(
                  t(result.error === "exists" ? "error.rename.exists" : "error.rename.invalid"),
                );
              }
            });
          }}
        >
          <label htmlFor={fieldId} className="field-label">
            {t("names.newName")}
          </label>
          <div className="field-row">
            <input
              id={fieldId}
              className="input"
              value={name}
              autoFocus
              spellCheck={false}
              aria-invalid={message ? true : undefined}
              aria-describedby={helpId}
              onChange={(event) => {
                setName(event.target.value);
                setServerError(null);
              }}
            />
            <button
              type="submit"
              className="button primary"
              aria-disabled={live !== null || action.pending}
            >
              {t("names.rename")}
            </button>
          </div>
          <p
            id={helpId}
            className={message ? "field-help error-text" : "field-help"}
            role={message ? "alert" : undefined}
          >
            {message ?? t("names.renameHelp")}
          </p>
        </form>
      ) : (
        <div className="group-actions">
          <button
            type="button"
            className="button secondary small"
            disabled={action.pending}
            title={t("names.ignoreHelp")}
            onClick={() => {
              void action.run(async () => {
                await backend.ignoreNameIssue(issue.id);
                onDone(null);
              });
            }}
          >
            {t("names.ignore")}
          </button>
          {canRename && (
            <button
              type="button"
              className="button primary small"
              onClick={() => {
                setEditing(true);
              }}
            >
              {t("names.rename")}
            </button>
          )}
        </div>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
    </section>
  );
}
