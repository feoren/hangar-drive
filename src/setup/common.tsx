// Pieces shared by the setup flows.

import { useId, useState } from "react";

import type {
  AccountFolder,
  DeviceNameError,
  FolderChoice,
  FolderPlace,
  NameError,
} from "../backend/types";
import { formatSize } from "../format";
import { nameProblem } from "../domain/names";
import { useLanguage, useT, type Translate } from "../i18n";
import { folderRefusalText } from "../main/BannerArea";
import { useBackend } from "../ui/backendContext";
import { FolderIcon } from "../ui/icons";
import { Feedback, Loading, PathText } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";

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
export function nameErrorText(error: DeviceNameError, t: Translate): string {
  switch (error) {
    case "blank":
      return t("name.blank");
    case "edgeWhitespace":
      return t("name.edgeWhitespace");
    case "looksLike":
      return t("devices.name.lookAlike");
  }
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
  /** The proposed place, or the one the person picked instead. */
  readonly place: FolderPlace;
  readonly checked: boolean;
}

function proposed(folder: AccountFolder): FolderPlace {
  return { path: folder.proposedPath, name: folder.name, token: folder.proposedToken };
}

/**
 * "Which folders should be on this device?" (UX 4.3 step 2, 4.4 step 5): all checked, each at a
 * proposed place. A place that already holds files is asked about natively by the shell, with
 * the place, the number of files and the server (6.5, security review H1); "Choose another
 * folder" there opens the picker for that folder here, and the folders joined meanwhile leave
 * the list.
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
  const action = useAction();

  const list =
    choices ??
    (loaded.status === "ready"
      ? loaded.data.folders.map((folder) => ({ folder, place: proposed(folder), checked: true }))
      : null);

  const update = (id: string, change: Partial<Choice>) => {
    if (!list) return;
    setChoices(list.map((choice) => (choice.folder.id === id ? { ...choice, ...change } : choice)));
  };

  /** Joins the checked folders; one declined natively gets the picker, the joined ones go. */
  const proceed = (chosen: readonly Choice[]) => {
    if (!list) return;
    void action.run(async () => {
      const declined = await backend.joinFolders(
        chosen.map((choice): FolderChoice => ({
          folderId: choice.folder.id,
          token: choice.place.token,
        })),
      );
      if (declined.length === 0) {
        onDone();
        return;
      }
      const joined = new Set(
        chosen.filter((choice) => !declined.includes(choice.folder.id)).map((c) => c.folder.id),
      );
      let rest = list.filter((choice) => !joined.has(choice.folder.id));
      const first = declined[0];
      if (first !== undefined) {
        const result = await backend.pickFolder({ kind: "account", folderId: first });
        if (result.kind === "picked") {
          rest = rest.map((choice) =>
            choice.folder.id === first ? { ...choice, place: result } : choice,
          );
        }
        if (result.kind === "refused")
          setMessage(folderRefusalText(result.reason, result.folder, t));
      }
      setChoices(rest);
    });
  };

  if (loaded.status === "loading" || !list) return <Loading />;
  if (loaded.status === "failed")
    return <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>;
  const free = loaded.data.free;
  const chosen = list.filter((choice) => choice.checked);
  const total = chosen.reduce((sum, choice) => sum + choice.folder.size, 0);

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
                <PathText path={choice.place.path} className="row-sub" />
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
                  if (result.kind === "picked") update(choice.folder.id, { place: result });
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
            setMessage(null);
            proceed(chosen);
          }}
        >
          {t("setup.done")}
        </button>
      </div>
    </div>
  );
}
