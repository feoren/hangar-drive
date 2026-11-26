// Additional device in two steps (UX 4.3): pair with the other device, then choose the folders.
// Also used for "Pair again" after this device was removed (UX 8.8).

import { useId, useRef, useState } from "react";

import type { PairError, PairWaiting } from "../backend/types";
import { useT, type Translate } from "../i18n";
import { useBackendEvent } from "../ui/appContext";
import { useBackend } from "../ui/backendContext";
import { Feedback, NumberRows } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";
import { FolderChoiceStep, StepIndicator } from "./common";
import { LinkField } from "./LinkField";

export function pairErrorText(error: PairError, t: Translate): string {
  switch (error) {
    case "notALink":
      return t("error.pair.notALink");
    case "expired":
      return t("error.pair.expired");
    case "typo":
      return t("error.pair.typo");
    case "declined":
      return t("error.pair.declined");
    case "tooMany":
      return t("error.pair.tooMany");
    case "otherAccount":
      return t("error.server.otherAccount");
    case "unreachable":
      return t("error.server.unreachable");
    case "insecure":
      return t("error.insecure", { app: t("app.name") });
  }
}

export function PairFlow({
  titleId,
  onBack,
  onDone,
}: {
  readonly titleId?: string;
  readonly onBack: () => void;
  readonly onDone: () => void;
}) {
  const ownTitle = useId();
  const title = titleId ?? ownTitle;
  const [paired, setPaired] = useState(false);
  if (paired) {
    return (
      <FolderChoiceStep
        titleId={title}
        step={<StepIndicator step={2} total={2} />}
        onDone={onDone}
      />
    );
  }
  return (
    <PairStep
      titleId={title}
      onBack={onBack}
      onJoined={() => {
        setPaired(true);
      }}
    />
  );
}

function PairStep({
  titleId,
  onBack,
  onJoined,
}: {
  readonly titleId: string;
  readonly onBack: () => void;
  readonly onJoined: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const app = t("app.name");
  const [typed, setTyped] = useState(false);
  const [link, setLink] = useState("");
  const [server, setServer] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [waiting, setWaiting] = useState<PairWaiting | null>(null);
  const [joined, setJoined] = useState(false);
  const action = useAction();
  // Set before the call, because the answer can arrive before the call returns.
  const pairing = useRef(false);
  const serverId = useId();
  const codeId = useId();

  useBackendEvent((event) => {
    if (event.type !== "pairResult" || !pairing.current) return;
    pairing.current = false;
    if (event.result.kind === "joined") {
      setWaiting((current) => current ?? { path: "link", safety: { groups: [] } });
      setJoined(true);
      setTimeout(onJoined, 900);
    } else {
      setWaiting(null);
      setError(pairErrorText(event.result.error, t));
    }
  });

  const start = (input: Parameters<typeof backend.startPairing>[0]) => {
    setError(null);
    pairing.current = true;
    void action.run(async () => {
      const result = await backend.startPairing(input);
      if (result.ok) {
        setWaiting((current) => current ?? result.value);
      } else {
        pairing.current = false;
        setError(pairErrorText(result.error, t));
      }
    });
  };

  if (waiting) {
    return (
      <div className="step-form">
        <StepIndicator step={1} total={2} />
        <h1 id={titleId} className="step-title" tabIndex={-1}>
          {t("pair.new.title")}
        </h1>
        {joined ? (
          <Feedback>{t("pair.joined")}</Feedback>
        ) : waiting.path === "typed" ? (
          <>
            <p className="step-body" role="status">
              {t("pair.new.waiting")}
            </p>
            <NumberRows rows={waiting.safety} label={t("safety.label")} />
          </>
        ) : (
          <>
            <p className="step-body" role="status">
              {t("pair.new.waitingLink")}
            </p>
            <details className="disclosure">
              <summary>{t("pair.numbers.show")}</summary>
              <NumberRows rows={waiting.safety} label={t("safety.label")} />
            </details>
          </>
        )}
        <div className="waiting-dots" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <div className="step-actions">
          <button
            type="button"
            className="button secondary"
            onClick={() => {
              void action.run(async () => {
                await backend.cancelPairing();
                pairing.current = false;
                setWaiting(null);
              });
            }}
          >
            {t("common.cancel")}
          </button>
          <span />
        </div>
      </div>
    );
  }

  const canStart = typed ? server.trim() !== "" && code.trim() !== "" : link.trim() !== "";
  return (
    <form
      className="step-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!canStart) return;
        start(
          typed
            ? { kind: "typed", server: server.trim(), code }
            : { kind: "link", link: link.trim() },
        );
      }}
    >
      <StepIndicator step={1} total={2} />
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("pair.new.title")}
      </h1>
      <p className="step-body">{t("pair.new.body", { app })}</p>
      {typed ? (
        <>
          <div className="field">
            <label htmlFor={serverId} className="field-label">
              {t("pair.new.serverLabel")}
            </label>
            <input
              id={serverId}
              className="input"
              value={server}
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              data-autofocus
              autoFocus
              placeholder="drive.example.org"
              onChange={(event) => {
                setServer(event.target.value);
                setError(null);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor={codeId} className="field-label">
              {t("pair.new.codeLabel")}
            </label>
            <input
              id={codeId}
              className="input code-input"
              value={code}
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              aria-invalid={error ? true : undefined}
              onChange={(event) => {
                setCode(event.target.value);
                setError(null);
              }}
            />
          </div>
          {error && <Feedback tone="error">{error}</Feedback>}
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setTyped(false);
              setError(null);
            }}
          >
            {t("pair.new.linkInstead")}
          </button>
        </>
      ) : (
        <>
          <LinkField
            label={t("pair.new.label")}
            value={link}
            autoFocus
            placeholder="hangar-drive://pair#…"
            onChange={(value) => {
              setLink(value);
              setError(null);
            }}
            onScanned={(value) => {
              start({ kind: "link", link: value });
            }}
            error={error}
          />
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setTyped(true);
              setError(null);
            }}
          >
            {t("pair.new.typeInstead")}
          </button>
        </>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <button type="button" className="button secondary" onClick={onBack}>
          {t("setup.back")}
        </button>
        <button
          type="submit"
          className="button primary"
          aria-disabled={!canStart || action.pending}
        >
          {t("pair.new.connect")}
        </button>
      </div>
    </form>
  );
}
