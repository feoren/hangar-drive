// Recovery with the sheet (UX 4.4): four screens, one decision each. The sheet (its link pasted
// or scanned, the code typed, the name of this device), remove the old devices, keep the new
// code, choose the folders. The link carries server, account and anchor, so nothing else is typed.

import { useEffect, useId, useState } from "react";

import type {
  DeviceId,
  InspectedLink,
  LinkError,
  LinkKind,
  NameError,
  RecoverError,
  RecoveryCode,
} from "../backend/types";
import { cleanName, nameProblem } from "../domain/names";
import { normalizeCode, splitGroups } from "../domain/codes";
import { cleanLink, groupHex } from "../domain/links";
import { formatRelative } from "../format";
import { useLanguage, useT, type Translate } from "../i18n";
import { useBackend, useNow } from "../ui/backendContext";
import { CheckIcon, DesktopIcon, LaptopIcon } from "../ui/icons";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { DeviceNameField, FolderChoiceStep, StepIndicator } from "./common";
import { LinkField, otherKind } from "./LinkField";
import { linkErrorText } from "./PairFlow";
import { RecoveryCodeStep } from "./RecoveryCodeStep";
import { CHECK_DELAY_MS } from "./NewAccountFlow";

const TOTAL = 4;

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
    case "wrongSheet":
      return t("error.recovery.wrongSheet");
    case "unreachable":
      return t("error.server.unreachable");
    case "insecure":
      return t("error.insecure", { app });
  }
}

export function RecoverFlow({
  initialLink = "",
  onSwitch,
  onBack,
  onDone,
}: {
  /** The sheet's link, when the OS handed it over. */
  readonly initialLink?: string;
  readonly onSwitch?: ((kind: LinkKind, link: string) => void) | undefined;
  readonly onBack: () => void;
  readonly onDone: () => void;
}) {
  const t = useT();
  const [step, setStep] = useState(1);
  const [code, setCode] = useState<RecoveryCode | null>(null);
  const [deviceName, setDeviceName] = useState("");
  const titleId = useId();
  const indicator = <StepIndicator step={step} total={TOTAL} />;

  switch (step) {
    case 1:
      return (
        <SheetStep
          titleId={titleId}
          step={indicator}
          initialLink={initialLink}
          onSwitch={onSwitch}
          onBack={onBack}
          onNext={(name) => {
            setDeviceName(name);
            setStep(2);
          }}
        />
      );
    case 2:
      return (
        <CleanupStep
          titleId={titleId}
          step={indicator}
          onNext={(next) => {
            setCode(next);
            setStep(3);
          }}
        />
      );
    case 3:
      return code ? (
        <RecoveryCodeStep
          code={code}
          titleId={titleId}
          step={indicator}
          intro={t("recover.newCode")}
          deviceName={deviceName}
          onConfirmed={() => {
            setStep(4);
          }}
        />
      ) : null;
    default:
      return <FolderChoiceStep titleId={titleId} step={indicator} onDone={onDone} />;
  }
}

type SheetCheck =
  | { readonly kind: "idle" }
  | { readonly kind: "ok"; readonly link: string; readonly info: InspectedLink }
  | { readonly kind: "error"; readonly link: string; readonly error: LinkError };

function SheetStep({
  titleId,
  step,
  initialLink,
  onSwitch,
  onBack,
  onNext,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly initialLink: string;
  readonly onSwitch: ((kind: LinkKind, link: string) => void) | undefined;
  readonly onBack: () => void;
  readonly onNext: (deviceName: string) => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [link, setLink] = useState(initialLink);
  const [check, setCheck] = useState<SheetCheck>({ kind: "idle" });
  const [code, setCode] = useState("");
  const [defaultName] = useLoad(() => backend.defaultDeviceName(), [backend]);
  const [name, setName] = useState<string | null>(null);
  const [refused, setRefused] = useState<NameError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const action = useAction();
  const codeId = useId();
  const helpId = useId();
  const groups = splitGroups(code);
  const clean = cleanLink(link);
  const foreign = otherKind(clean, "recover") !== null;
  const deviceName = name ?? (defaultName.status === "ready" ? defaultName.data : "");

  // The link is read offline while typing pauses; it names server and account before the code.
  useEffect(() => {
    if (clean === "" || foreign) return;
    let current = true;
    const timer = setTimeout(() => {
      backend.inspectLink(clean).then(
        (result) => {
          if (!current) return;
          setCheck(
            result.ok
              ? { kind: "ok", link: clean, info: result.value }
              : { kind: "error", link: clean, error: result.error },
          );
        },
        (failure: unknown) => {
          if (current) {
            setCheck({ kind: "idle" });
            console.error("Hangar Drive: reading the sheet's link failed", failure);
          }
        },
      );
    }, CHECK_DELAY_MS);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [backend, clean, foreign]);

  const state: SheetCheck =
    clean === "" || foreign || ("link" in check && check.link !== clean) ? { kind: "idle" } : check;
  const wrongKind = state.kind === "ok" && state.info.kind !== "recover";
  const linkError =
    state.kind === "error"
      ? linkErrorText(state.error, t("error.recover.notALink"), t)
      : wrongKind
        ? t("error.recover.notALink")
        : null;
  const found = state.kind === "ok" && state.info.kind === "recover" ? state.info : null;
  const ready = found !== null && code.trim() !== "" && nameProblem(deviceName) === null;

  return (
    <form
      className="step-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready || action.pending) return;
        setError(null);
        const sentName = cleanName(deviceName);
        void action.run(async () => {
          const result = await backend.recoverAccount(clean, normalizeCode(code), sentName);
          if (result.ok) onNext(sentName);
          else if (result.error === "blank" || result.error === "edgeWhitespace") {
            setRefused(result.error);
          } else setError(recoverErrorText(result.error, t));
        });
      }}
    >
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recover.title")}
      </h1>
      <p className="step-body">{t("recover.body")}</p>
      <LinkField
        label={t("recover.linkLabel")}
        expect="recover"
        value={link}
        autoFocus
        placeholder="hangar-drive://recover#…"
        onChange={(value) => {
          setLink(value);
          setError(null);
        }}
        onSwitch={onSwitch}
        error={linkError}
        status={
          found && (
            <>
              <p className="field-help ok-text">
                <CheckIcon size={16} />
                {t("recover.linkOk", { host: found.host })}
              </p>
              <p className="field-help">
                {t("recover.linkAccount", { account: groupHex(found.account) })}
              </p>
            </>
          )
        }
      />
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
      {found && (
        <DeviceNameField
          value={deviceName}
          refused={refused}
          onChange={(next) => {
            setRefused(null);
            setName(next);
          }}
        />
      )}
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
  const finish = (remove: readonly DeviceId[]) => {
    void action.run(async () => {
      // Removing devices asks natively with their names (follow-up check N-2); after a "no"
      // there the step stays as it is.
      const code = await backend.finishRecoveryCleanup(remove);
      if (code !== null) onNext(code);
    });
  };
  // No old device left in the account: nothing to decide, the step passes by itself.
  const nothingToRemove = devices.status === "ready" && devices.data.length === 0;
  useEffect(() => {
    if (nothingToRemove) finish([]);
    // Runs once, when the empty list arrives.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nothingToRemove]);

  return (
    <div className="step-form">
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recover.cleanup.title")}
      </h1>
      {!nothingToRemove && <p className="step-body">{t("recover.cleanup.body")}</p>}
      {(devices.status === "loading" || (nothingToRemove && action.error === null)) && <Loading />}
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
            finish(
              devices.data.filter((device) => !kept.has(device.id)).map((device) => device.id),
            );
          }}
        >
          {t("setup.next")}
        </button>
      </div>
    </div>
  );
}
