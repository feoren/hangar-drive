// The recovery code (UX 4.2 step 2), also used after a recovery (4.4) and for a new code (10.3):
// show it, keep it (print, file, copy), then type one group back. The step cannot be skipped.
// The sheet (version 2) also carries the server, the account and the link to paste during a
// recovery; they sit folded under the code, because only the code needs attention here.

import { useId, useState, type ReactNode } from "react";

import type { RecoveryCode } from "../backend/types";
import { normalizeCode } from "../domain/codes";
import { groupHex } from "../domain/links";
import { useLanguage, useT } from "../i18n";
import { useBackend, useNow } from "../ui/backendContext";
import { CodeGroups, Feedback } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";
import { recoverySheetDocument } from "./recoverySheet";

/** Characters in one group of the recovery code. */
const GROUP_LENGTH = 4;

interface Props {
  readonly code: RecoveryCode;
  /** The title element id, so the surrounding dialog or page can point at it. */
  readonly titleId: string;
  /** "Step 2 of 3" above the title, or nothing. */
  readonly step?: ReactNode;
  /** A sentence before the code ("The old code is used up now ..."). */
  readonly intro?: string;
  readonly onConfirmed: () => void;
  /** Extra buttons on the left of the action row (Back, Cancel). */
  readonly secondary?: ReactNode;
  /** The device that made the code, printed on the sheet. */
  readonly deviceName?: string | undefined;
}

export function RecoveryCodeStep({
  code,
  titleId,
  step,
  intro,
  onConfirmed,
  secondary,
  deviceName,
}: Props) {
  const t = useT();
  const language = useLanguage();
  const now = useNow();
  const backend = useBackend();
  const sheetDocument = () => recoverySheetDocument(code, t, language, now, deviceName);
  const [phase, setPhase] = useState<"show" | "check">("show");
  /** `again`: the place was refused, offer to choose another one right at the message. */
  const [feedback, setFeedback] = useState<{
    tone: "ok" | "error";
    text: string;
    again?: boolean;
  } | null>(null);
  const [typed, setTyped] = useState("");
  const [wrong, setWrong] = useState(false);
  const action = useAction();
  const inputId = useId();
  const messageId = useId();

  const confirm = (value: string) => {
    if (value.trim() === "") return;
    void action.run(async () => {
      const check = await backend.confirmRecoveryGroup(normalizeCode(value));
      // "declined": the person kept the old code in the native question; nothing to say.
      if (check === "confirmed") onConfirmed();
      else if (check === "wrong") setWrong(true);
    });
  };

  if (phase === "check") {
    return (
      <form
        className="step-form"
        onSubmit={(event) => {
          event.preventDefault();
          confirm(typed);
        }}
      >
        {step}
        <h1 id={titleId} className="step-title" tabIndex={-1}>
          {t("recovery.check.title")}
        </h1>
        <p className="step-body">{t("recovery.check.body", { group: code.checkGroup })}</p>
        <div className="field">
          <label htmlFor={inputId} className="field-label">
            {t("recovery.check.label", { group: code.checkGroup })}
          </label>
          <input
            id={inputId}
            className="input code-input"
            value={typed}
            maxLength={8}
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            data-autofocus
            autoFocus
            aria-invalid={wrong ? true : undefined}
            aria-describedby={messageId}
            onChange={(event) => {
              const value = event.target.value;
              setTyped(value);
              setWrong(false);
              // A whole group is checked at once, so the person does not need the button.
              if (normalizeCode(value).length === GROUP_LENGTH) confirm(value);
            }}
          />
          <div id={messageId} className="field-message" aria-live="polite">
            {wrong && <p className="field-help error-text">{t("recovery.check.wrong")}</p>}
          </div>
        </div>
        {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
        <div className="step-actions">
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setPhase("show");
              setTyped("");
              setWrong(false);
            }}
          >
            {t("recovery.check.showAgain")}
          </button>
          <button
            type="submit"
            className="button primary"
            aria-disabled={typed.trim() === "" || action.pending}
          >
            {t("recovery.check.confirm")}
          </button>
        </div>
      </form>
    );
  }

  /** "Save as file": a place in a synced or cloud folder is refused, with a way to try again. */
  const save = () => {
    setFeedback(null);
    void action.run(async () => {
      const result = await backend.saveRecoveryFile(sheetDocument());
      if (result.kind === "saved")
        setFeedback({ tone: "ok", text: t("recovery.saved", { path: result.path }) });
      if (result.kind === "inSyncFolder")
        setFeedback({ tone: "error", text: t("error.recovery.savedInSync"), again: true });
      if (result.kind === "inCloudFolder")
        setFeedback({ tone: "error", text: t("error.recovery.savedInCloud"), again: true });
    });
  };

  const keep = (run: () => Promise<string | null>) => {
    setFeedback(null);
    void action.run(async () => {
      const text = await run();
      if (text) setFeedback({ tone: "ok", text });
    });
  };

  return (
    <div className="step-form">
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recovery.title")}
      </h1>
      {intro && <p className="step-body">{intro}</p>}
      <p className="step-body">{t("recovery.body")}</p>
      <CodeGroups groups={code.groups} label={t("recovery.codeLabel")} />
      {/* Keeping the code comes right after it; what else the sheet says waits below. */}
      <div className="keep-actions">
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            keep(async () => {
              await backend.printRecoverySheet(sheetDocument());
              return null;
            });
          }}
        >
          {t("recovery.print")}
        </button>
        <button type="button" className="button secondary" disabled={action.pending} onClick={save}>
          {t("recovery.save")}
        </button>
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            keep(async () => {
              await backend.copyRecoveryCode();
              return t("recovery.copied");
            });
          }}
        >
          {t("recovery.copy")}
        </button>
      </div>
      {feedback && (
        <Feedback
          tone={feedback.tone}
          action={
            feedback.again ? (
              <button
                type="button"
                className="button secondary small"
                disabled={action.pending}
                onClick={save}
              >
                {t("recovery.saveElsewhere")}
              </button>
            ) : undefined
          }
        >
          {feedback.text}
        </Feedback>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <p className="step-note">{t("recovery.keepSafe")}</p>
      <details className="disclosure">
        <summary>{t("sheet.more")}</summary>
        <dl className="facts">
          <dt>{t("pair.check.server")}</dt>
          <dd>{code.sheet.serverUrl}</dd>
          <dt>{t("sheet.accountId")}</dt>
          <dd>{groupHex(code.sheet.accountId)}</dd>
          <dt>{t("sheet.link")}</dt>
          <dd>{code.sheet.link}</dd>
        </dl>
      </details>
      <div className="step-actions">
        {secondary ?? <span />}
        <button
          type="button"
          className="button primary"
          onClick={() => {
            setPhase("check");
          }}
        >
          {t("recovery.confirmSaved")}
        </button>
      </div>
    </div>
  );
}
