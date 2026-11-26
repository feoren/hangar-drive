// Recovery with the sheet (UX 4.4): five screens, one decision each. Enter the sheet, name the
// device, remove the old devices, keep the new code, choose the folders.

import { useId, useState } from "react";

import type { DeviceId, NameError, RecoverError, RecoveryCode } from "../backend/types";
import { cleanName, nameProblem } from "../domain/names";
import { splitGroups } from "../domain/codes";
import { formatRelative } from "../format";
import { useLanguage, useT, type Translate } from "../i18n";
import { useBackend, useNow } from "../ui/backendContext";
import { DesktopIcon, LaptopIcon } from "../ui/icons";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { DeviceNameField, FolderChoiceStep, StepIndicator } from "./common";
import { RecoveryCodeStep } from "./RecoveryCodeStep";

const TOTAL = 5;

export function recoverErrorText(error: RecoverError, t: Translate): string {
  const app = t("app.name");
  switch (error) {
    case "typo":
      return t("error.recovery.typo");
    case "unknown":
      return t("error.recovery.unknown");
    case "used":
      return t("error.recovery.used");
    case "otherApp":
      return t("error.recovery.otherApp", { app });
    case "unreachable":
      return t("error.server.unreachable");
    case "insecure":
      return t("error.insecure", { app });
  }
}

export function RecoverFlow({
  onBack,
  onDone,
}: {
  readonly onBack: () => void;
  readonly onDone: () => void;
}) {
  const t = useT();
  const [step, setStep] = useState(1);
  const [code, setCode] = useState<RecoveryCode | null>(null);
  const titleId = useId();
  const indicator = <StepIndicator step={step} total={TOTAL} />;

  switch (step) {
    case 1:
      return (
        <SheetStep
          titleId={titleId}
          step={indicator}
          onBack={onBack}
          onNext={() => {
            setStep(2);
          }}
        />
      );
    case 2:
      return (
        <NameStep
          titleId={titleId}
          step={indicator}
          onNext={() => {
            setStep(3);
          }}
        />
      );
    case 3:
      return (
        <CleanupStep
          titleId={titleId}
          step={indicator}
          onNext={(next) => {
            setCode(next);
            setStep(4);
          }}
        />
      );
    case 4:
      return code ? (
        <RecoveryCodeStep
          code={code}
          titleId={titleId}
          step={indicator}
          intro={t("recover.newCode")}
          onConfirmed={() => {
            setStep(5);
          }}
        />
      ) : null;
    default:
      return <FolderChoiceStep titleId={titleId} step={indicator} onDone={onDone} />;
  }
}

function SheetStep({
  titleId,
  step,
  onBack,
  onNext,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly onBack: () => void;
  readonly onNext: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [server, setServer] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const action = useAction();
  const serverId = useId();
  const codeId = useId();
  const helpId = useId();
  const groups = splitGroups(code);
  const ready = server.trim() !== "" && code.trim() !== "";

  return (
    <form
      className="step-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready) return;
        setError(null);
        void action.run(async () => {
          const result = await backend.recoverAccount(server.trim(), code);
          if (result.ok) onNext();
          else setError(recoverErrorText(result.error, t));
        });
      }}
    >
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recover.title")}
      </h1>
      <p className="step-body">{t("recover.body")}</p>
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
          {t("recover.codeLabel")}
        </label>
        <input
          id={codeId}
          className="input code-input wide"
          value={code}
          autoComplete="off"
          autoCapitalize="characters"
          spellCheck={false}
          aria-describedby={helpId}
          aria-invalid={error ? true : undefined}
          onChange={(event) => {
            setCode(event.target.value);
            setError(null);
          }}
        />
        <p id={helpId} className="field-help code-preview" aria-hidden={groups.length === 0}>
          {groups.join(" ")}
        </p>
      </div>
      {error && <Feedback tone="error">{error}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <button type="button" className="button secondary" onClick={onBack}>
          {t("setup.back")}
        </button>
        <button type="submit" className="button primary" aria-disabled={!ready || action.pending}>
          {t("setup.next")}
        </button>
      </div>
    </form>
  );
}

function NameStep({
  titleId,
  step,
  onNext,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly onNext: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [defaultName] = useLoad(() => backend.defaultDeviceName(), [backend]);
  const [name, setName] = useState<string | null>(null);
  const [refused, setRefused] = useState<NameError | null>(null);
  const action = useAction();
  const value = name ?? (defaultName.status === "ready" ? defaultName.data : "");
  const blocked = nameProblem(value) !== null;
  return (
    <form
      className="step-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (blocked) return;
        void action.run(async () => {
          const result = await backend.setDeviceName(cleanName(value));
          if (result.ok) onNext();
          else setRefused(result.error);
        });
      }}
    >
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recover.name.title")}
      </h1>
      <DeviceNameField
        value={value}
        refused={refused}
        onChange={(next) => {
          setRefused(null);
          setName(next);
        }}
      />
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <span />
        <button type="submit" className="button primary" aria-disabled={blocked || action.pending}>
          {t("setup.next")}
        </button>
      </div>
    </form>
  );
}

function CleanupStep({
  titleId,
  step,
  onNext,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly onNext: (code: RecoveryCode) => void;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const now = useNow();
  const [devices] = useLoad(() => backend.recoveryDevices(), [backend]);
  const [kept, setKept] = useState<ReadonlySet<DeviceId>>(new Set());
  const action = useAction();

  return (
    <div className="step-form">
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recover.cleanup.title")}
      </h1>
      <p className="step-body">{t("recover.cleanup.body")}</p>
      {devices.status === "loading" && <Loading />}
      {devices.status === "failed" && (
        <Feedback tone="error">{errorText(devices.error, t)}</Feedback>
      )}
      {devices.status === "ready" && (
        <ul className="choice-list">
          {devices.data.map((device) => (
            <li key={device.id} className="choice-row">
              <label className="choice-check">
                <input
                  type="checkbox"
                  checked={!kept.has(device.id)}
                  aria-label={t("recover.cleanup.remove", { device: device.name })}
                  onChange={(event) => {
                    const next = new Set(kept);
                    if (event.target.checked) next.delete(device.id);
                    else next.add(device.id);
                    setKept(next);
                  }}
                />
                {device.kind === "laptop" ? <LaptopIcon /> : <DesktopIcon />}
                <span className="choice-text">
                  <span className="row-name">{device.name}</span>
                  {device.lastSeen !== null && (
                    <span className="row-sub">
                      {t("devices.lastSeen", {
                        when: formatRelative(language, device.lastSeen, now),
                      })}
                    </span>
                  )}
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <span />
        <button
          type="button"
          className="button primary"
          aria-disabled={devices.status !== "ready" || action.pending}
          onClick={() => {
            if (devices.status !== "ready") return;
            const remove = devices.data
              .filter((device) => !kept.has(device.id))
              .map((device) => device.id);
            void action.run(async () => {
              onNext(await backend.finishRecoveryCleanup(remove));
            });
          }}
        >
          {t("setup.next")}
        </button>
      </div>
    </div>
  );
}
