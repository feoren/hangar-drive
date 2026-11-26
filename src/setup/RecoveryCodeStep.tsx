// The recovery code (UX 4.2 step 2), also used after a recovery (4.4) and for a new code (10.3):
// show it, keep it (print, file, copy), then type one group back. The step cannot be skipped.

import { useId, useState, type ReactNode } from "react";

import type { RecoveryCode } from "../backend/types";
import { normalizeCode } from "../domain/codes";
import { useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { CodeGroups, Feedback } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";

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
}

export function RecoveryCodeStep({ code, titleId, step, intro, onConfirmed, secondary }: Props) {
  const t = useT();
  const backend = useBackend();
  const [phase, setPhase] = useState<"show" | "check">("show");
  const [feedback, setFeedback] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [typed, setTyped] = useState("");
  const [wrong, setWrong] = useState(false);
  const action = useAction();
  const inputId = useId();
  const messageId = useId();

  if (phase === "check") {
    return (
      <form
        className="step-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (typed.trim() === "") return;
          void action.run(async () => {
            const ok = await backend.confirmRecoveryGroup(normalizeCode(typed));
            if (ok) onConfirmed();
            else setWrong(true);
          });
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
              setTyped(event.target.value);
              setWrong(false);
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
      <div className="keep-actions">
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            keep(async () => {
              await backend.printRecoverySheet();
              return null;
            });
          }}
        >
          {t("recovery.print")}
        </button>
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            setFeedback(null);
            void action.run(async () => {
              const result = await backend.saveRecoveryFile();
              if (result.kind === "saved")
                setFeedback({ tone: "ok", text: t("recovery.saved", { path: result.path }) });
              if (result.kind === "inSyncFolder") {
                setFeedback({ tone: "error", text: t("error.recovery.savedInSync") });
              }
            });
          }}
        >
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
      {feedback && <Feedback tone={feedback.tone}>{feedback.text}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <p className="step-note">{t("recovery.keepSafe")}</p>
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
