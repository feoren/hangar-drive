// Recovery with the sheet (UX 4.4): four screens, one decision each. The sheet (its link pasted
// or scanned, the code typed, the name of this device), remove the old devices, keep the new
// code, choose the folders. The link carries server, account and anchor, so nothing else is typed.
// Nothing changes in the account before "Recover" on the second screen: that one step adds this
// device and removes the chosen devices and the used code (ADR 0001, "the engine on the recovery
// in one piece").

import { useEffect, useId, useState } from "react";

import type {
  Device,
  DeviceId,
  InspectedLink,
  LinkError,
  LinkKind,
  NameError,
  RecoverError,
  RecoveryCode,
  RecoveryEnded,
} from "../backend/types";
import { cleanName, nameProblem } from "../domain/names";
import { normalizeCode, splitGroups } from "../domain/codes";
import { cleanLink, groupHex } from "../domain/links";
import { formatLongDate, formatLongDateTime, formatRelative } from "../format";
import { useLanguage, useT, type Language, type Translate } from "../i18n";
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

/** Why the recovery ended in its last step, and that it starts again. */
export function recoveryEndedText(reason: RecoveryEnded, t: Translate): string {
  return `${t("recover.ended")} ${recoverErrorText(reason, t)}`;
}

/**
 * How the list of old devices names a device: its name, else (before this device joined, when
 * the names are sealed) the day it was added, with the time when two share that day.
 */
export function recoveryDeviceLabel(
  device: Device,
  all: readonly Device[],
  language: Language,
  t: Translate,
): string {
  if (device.name.trim() !== "") return device.name;
  const day = formatLongDate(language, device.added);
  const shared = all.some(
    (other) =>
      other.id !== device.id &&
      other.name.trim() === "" &&
      formatLongDate(language, other.added) === day,
  );
  return t("recover.cleanup.device", {
    date: shared ? formatLongDateTime(language, device.added) : day,
  });
}

export function RecoverFlow({
  initialLink = "",
  onSwitch,
  onBack,
  onHold,
  onDone,
}: {
  /** The sheet's link, when the OS handed it over. */
  readonly initialLink?: string;
  readonly onSwitch?: ((kind: LinkKind, link: string) => void) | undefined;
  readonly onBack: () => void;
  /** Keeps the setup on screen once the account exists, for the new code and the folders. */
  readonly onHold: (hold: boolean) => void;
  readonly onDone: () => void;
}) {
  const t = useT();
  const [step, setStep] = useState(1);
  const [code, setCode] = useState<RecoveryCode | null>(null);
  const [deviceName, setDeviceName] = useState("");
  const [sheetLink, setSheetLink] = useState(initialLink);
  // Counts the starts, so starting again shows a fresh first screen.
  const [round, setRound] = useState(0);
  const titleId = useId();
  const indicator = <StepIndicator step={step} total={TOTAL} />;

  switch (step) {
    case 1:
      return (
        <SheetStep
          key={round}
          titleId={titleId}
          step={indicator}
          initialLink={sheetLink}
          onSwitch={onSwitch}
          onHold={onHold}
          onBack={onBack}
          onNext={(name, link) => {
            setDeviceName(name);
            setSheetLink(link);
            setStep(2);
          }}
        />
      );
    case 2:
      return (
        <CleanupStep
          titleId={titleId}
          step={indicator}
          onHold={onHold}
          onBack={() => {
            onHold(false);
            onBack();
          }}
          onRestart={() => {
            onHold(false);
            setRound((last) => last + 1);
            setStep(1);
          }}
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
  onHold,
  onBack,
  onNext,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly initialLink: string;
  readonly onSwitch: ((kind: LinkKind, link: string) => void) | undefined;
  readonly onHold: (hold: boolean) => void;
  readonly onBack: () => void;
  readonly onNext: (deviceName: string, link: string) => void;
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
          // With an earlier attempt pending (security review "recovery" H1), this call lets the
          // new device join first, so the account can come into being right here: the setup
          // stays on screen for the old devices, the new code and the folders.
          onHold(true);
          let result: Awaited<ReturnType<typeof backend.recoverAccount>>;
          try {
            result = await backend.recoverAccount(clean, normalizeCode(code), sentName);
          } catch (failure) {
            onHold(false);
            throw failure;
          }
          if (result.ok) {
            onNext(sentName, clean);
            return;
          }
          onHold(false);
          if (result.error === "blank" || result.error === "edgeWhitespace") {
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
  onHold,
  onBack,
  onRestart,
  onNext,
}: {
  readonly titleId: string;
  readonly step: React.ReactNode;
  readonly onHold: (hold: boolean) => void;
  readonly onBack: () => void;
  readonly onRestart: () => void;
  readonly onNext: (code: RecoveryCode) => void;
}) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const now = useNow();
  const [devices, reloadDevices] = useLoad(() => backend.recoveryDevices(), [backend]);
  // Every old device starts chosen: who recovers has usually lost them, and a device left in
  // the account keeps reading it. Keeping all of them stays possible. A device that turns up
  // later starts chosen as well.
  const [kept, setKept] = useState<ReadonlySet<DeviceId>>(new Set());
  const [ended, setEnded] = useState<RecoveryEnded | null>(null);
  const [changed, setChanged] = useState(false);
  const [unreachable, setUnreachable] = useState(false);
  const action = useAction();
  const confirm = t("recover.cleanup.confirm");
  const finish = (remove: readonly DeviceId[]) => {
    void action.run(async () => {
      // The account comes into being in this call; the setup stays on screen for the new code
      // although the snapshot then says "done". After "unreachable" or a thrown error it stays
      // held, because the append may have gone through (the engine then finishes the join by
      // itself), and the same step finishes the recovery.
      onHold(true);
      setChanged(false);
      setUnreachable(false);
      // Removing devices asks natively and names them (follow-up check N-2); after a "no"
      // there the step stays as it is.
      const result = await backend.finishRecoveryCleanup(remove);
      if (result.ok) {
        if (result.value === null) onHold(false);
        else onNext(result.value);
        return;
      }
      switch (result.error) {
        case "unreachable":
          setUnreachable(true);
          break;
        case "listChanged":
          // Nothing was written: the person chooses again from the account's devices as they
          // are now (security review "recovery" M1).
          onHold(false);
          setChanged(true);
          reloadDevices();
          break;
        default:
          onHold(false);
          setEnded(result.error);
      }
    });
  };
  // No old device left in the account: nothing to decide, the step passes by itself.
  const nothingToRemove = devices.status === "ready" && devices.data.length === 0;
  useEffect(() => {
    if (nothingToRemove) finish([]);
    // Runs once, when the empty list arrives.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nothingToRemove]);

  if (ended !== null) {
    return (
      <div className="step-form">
        {step}
        <h1 id={titleId} className="step-title" tabIndex={-1}>
          {t("recover.cleanup.title")}
        </h1>
        <Feedback tone="error">{recoveryEndedText(ended, t)}</Feedback>
        <div className="step-actions">
          <button type="button" className="button secondary" onClick={onBack}>
            {t("common.cancel")}
          </button>
          <button type="button" className="button primary" data-autofocus onClick={onRestart}>
            {t("recover.restart")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="step-form">
      {step}
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("recover.cleanup.title")}
      </h1>
      {!nothingToRemove && <p className="step-body">{t("recover.cleanup.body")}</p>}
      {changed && <Feedback tone="info">{t("recover.cleanup.changed")}</Feedback>}
      {(devices.status === "loading" || (nothingToRemove && action.error === null)) && <Loading />}
      {devices.status === "failed" && (
        <Feedback tone="error">{errorText(devices.error, t)}</Feedback>
      )}
      {devices.status === "ready" && (
        <ul className="choice-list">
          {devices.data.map((device) => {
            const label = recoveryDeviceLabel(device, devices.data, language, t);
            return (
              <li key={device.id} className="choice-row">
                <label className="choice-check">
                  <input
                    type="checkbox"
                    checked={!kept.has(device.id)}
                    aria-label={t("recover.cleanup.remove", { device: label })}
                    onChange={(event) => {
                      const next = new Set(kept);
                      if (event.target.checked) next.delete(device.id);
                      else next.add(device.id);
                      setKept(next);
                    }}
                  />
                  {device.kind === "laptop" ? <LaptopIcon /> : <DesktopIcon />}
                  <span className="choice-text">
                    <span className="row-name">{label}</span>
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
            );
          })}
        </ul>
      )}
      {!nothingToRemove && (
        <p className="step-note">{t("recover.cleanup.note", { button: confirm })}</p>
      )}
      {unreachable && <Feedback tone="error">{t("error.server.unreachable")}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <button type="button" className="button secondary" onClick={onBack}>
          {t("common.cancel")}
        </button>
        <button
          type="button"
          className="button primary"
          aria-disabled={devices.status !== "ready" || action.pending}
          onClick={() => {
            if (devices.status !== "ready" || action.pending) return;
            finish(
              devices.data.filter((device) => !kept.has(device.id)).map((device) => device.id),
            );
          }}
        >
          {/* After a failure the same step finishes the recovery (the engine kept the choice,
              or completes the pending recovery), so the button says so. */}
          {unreachable || action.error !== null ? t("recover.cleanup.retry") : confirm}
        </button>
      </div>
    </div>
  );
}
