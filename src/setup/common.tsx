// Pieces shared by the setup flows.

import { useId, useState } from "react";

import type { AccountFolder, FolderChoice, NameError } from "../backend/types";
import { formatSize } from "../format";
import { nameProblem } from "../domain/names";
import { useLanguage, useT, type Translate } from "../i18n";
import { folderRefusalText } from "../main/BannerArea";
import { useBackend } from "../ui/backendContext";
import { FolderIcon } from "../ui/icons";
import { Feedback, Loading, PathText } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { MergeDialog } from "./MergeDialog";

/** "Schritt 1 von 3" with a quiet bar of segments: the steps really are a sequence (UX 4.2). */
export function StepIndicator({ step, total }: { readonly step: number; readonly total: number }) {
  const t = useT();
  return (
    <div className="step-indicator">
      <p className="step-count">{t("setup.step", { step, total })}</p>
      <div className="step-bar" aria-hidden="true">
        {Array.from({ length: total }, (_, index) => (
          <span key={index} className={index < step ? "step-seg done" : "step-seg"} />
        ))}
      </div>
    </div>
  );
}

/** The device name field, prefilled with the computer name (UX 4.2 step 1). */
/** The words for a refused name (rule N5), shown at the field. */
export function nameErrorText(error: NameError, t: Translate): string {
  return error === "blank" ? t("name.blank") : t("name.edgeWhitespace");
}

export function DeviceNameField({
  value,
  onChange,
  refused = null,
}: {
  readonly value: string;
  readonly onChange: (value: string) => void;
  /** What the backend answered for the last name sent, until the name changes. */
  readonly refused?: NameError | null;
}) {
  const t = useT();
  const id = useId();
  const helpId = useId();
  const problem = nameProblem(value) ?? refused;
  const empty = problem !== null;
  return (
    <div className="field">
      <label htmlFor={id} className="field-label">
        {t("setup.deviceName.label")}
      </label>
      <input
        id={id}
        className="input"
        value={value}
        maxLength={64}
        autoComplete="off"
        aria-describedby={helpId}
        aria-invalid={empty ? true : undefined}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
      <p id={helpId} className={empty ? "field-help error-text" : "field-help"}>
        {problem ? nameErrorText(problem, t) : t("setup.deviceName.help")}
      </p>
    </div>
  );
}

interface Choice {
  readonly folder: AccountFolder;
  readonly path: string;
  readonly checked: boolean;
}

/**
 * "Which folders should be on this device?" (UX 4.3 step 2, 4.4 step 5): all checked, each at a
 * proposed place. A place that already holds files asks the merge question first (6.5).
 */
export function FolderChoiceStep({
  titleId,
  step,
  onDone,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly onDone: () => void;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const [loaded] = useLoad(() => backend.listAccountFolders(), [backend]);
  const [choices, setChoices] = useState<readonly Choice[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [asking, setAsking] = useState<{
    queue: readonly Choice[];
    done: readonly FolderChoice[];
  } | null>(null);
  const action = useAction();

  const list =
    choices ??
    (loaded.status === "ready"
      ? loaded.data.folders.map((folder) => ({ folder, path: folder.proposedPath, checked: true }))
      : null);

  const update = (id: string, change: Partial<Choice>) => {
    if (!list) return;
    setChoices(list.map((choice) => (choice.folder.id === id ? { ...choice, ...change } : choice)));
  };

  /** Walks the checked folders; one that is not empty stops at the merge question. */
  const proceed = (queue: readonly Choice[], done: readonly FolderChoice[]) => {
    void action.run(async () => {
      const rest = [...queue];
      const accepted = [...done];
      while (rest.length > 0) {
        const next = rest[0];
        if (!next) break;
        const count = await backend.countLocalFiles(next.path);
        if (count > 0) {
          setAsking({ queue: rest, done: accepted });
          return;
        }
        accepted.push({ folderId: next.folder.id, path: next.path });
        rest.shift();
      }
      setAsking(null);
      await backend.joinFolders(accepted);
      onDone();
    });
  };

  if (loaded.status === "loading" || !list) return <Loading />;
  if (loaded.status === "failed")
    return <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>;
  const free = loaded.data.free;
  const chosen = list.filter((choice) => choice.checked);
  const total = chosen.reduce((sum, choice) => sum + choice.folder.size, 0);
  const current = asking?.queue[0];

  return (
    <div className="step-form">
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("pair.folders.title")}
      </h1>
      <ul className="choice-list">
        {list.map((choice) => (
          <li key={choice.folder.id} className="choice-row">
            <label className="choice-check">
              <input
                type="checkbox"
                checked={choice.checked}
                onChange={(event) => {
                  update(choice.folder.id, { checked: event.target.checked });
                }}
              />
              <FolderIcon />
              <span className="choice-text">
                <span className="row-name">{choice.folder.name}</span>
                <PathText path={choice.path} className="row-sub" />
              </span>
              <span className="choice-size">{formatSize(language, choice.folder.size)}</span>
            </label>
            <button
              type="button"
              className="button secondary small"
              aria-label={`${t("folder.setup.change")}: ${choice.folder.name}`}
              disabled={action.pending}
              onClick={() => {
                setMessage(null);
                void action.run(async () => {
                  const result = await backend.pickFolder({
                    kind: "account",
                    folderId: choice.folder.id,
                  });
                  if (result.kind === "picked") update(choice.folder.id, { path: result.path });
                  if (result.kind === "refused")
                    setMessage(folderRefusalText(result.reason, result.folder, t));
                });
              }}
            >
              {t("folder.setup.change")}
            </button>
          </li>
        ))}
      </ul>
      <p className={total > free ? "space-line warn-text" : "space-line"}>
        {total > free
          ? t("pair.folders.tooBig", { size: formatSize(language, total - free) })
          : t("pair.folders.free", { size: formatSize(language, free) })}
      </p>
      {message && <Feedback tone="error">{message}</Feedback>}
      {chosen.length === 0 && <p className="field-help">{t("pair.folders.none")}</p>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <span />
        <button
          type="button"
          className="button primary"
          aria-disabled={chosen.length === 0 || action.pending}
          onClick={() => {
            if (chosen.length === 0) return;
            proceed(chosen, []);
          }}
        >
          {t("setup.done")}
        </button>
      </div>
      {asking && current && (
        <MergeDialog
          folderId={current.folder.id}
          folderName={current.folder.name}
          path={current.path}
          onMerge={(path) => {
            update(current.folder.id, { path });
            const accepted = [...asking.done, { folderId: current.folder.id, path }];
            setAsking(null);
            proceed(asking.queue.slice(1), accepted);
            return Promise.resolve();
          }}
          onClose={() => {
            setAsking(null);
          }}
        />
      )}
    </div>
  );
}
