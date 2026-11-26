// New account in three steps (UX 4.2): connect with the invite link, keep the recovery code,
// choose the folder. The invite is checked while typing, so an expired link shows up in step 1.

import { useEffect, useId, useState } from "react";

import type { FolderPlace, InviteError, NameError, RecoveryCode } from "../backend/types";
import { cleanName, nameProblem } from "../domain/names";
import { useT, type Translate } from "../i18n";
import { folderRefusalText } from "../main/BannerArea";
import { useBackend } from "../ui/backendContext";
import { CheckIcon, FolderIcon } from "../ui/icons";
import { Feedback, Loading, PathText } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { DeviceNameField, StepIndicator } from "./common";
import { LinkField } from "./LinkField";
import { RecoveryCodeStep } from "./RecoveryCodeStep";

export function inviteErrorText(error: InviteError, t: Translate): string {
  switch (error) {
    case "notALink":
      return t("error.invite.notALink");
    case "used":
      return t("error.invite.used");
    case "expired":
      return t("error.invite.expired");
    case "unreachable":
      return t("error.invite.unreachable");
    case "insecure":
      return t("error.insecure", { app: t("app.name") });
  }
}

type Check =
  | { readonly kind: "idle" }
  | { readonly kind: "checking"; readonly link: string }
  | { readonly kind: "ok"; readonly link: string; readonly host: string }
  | { readonly kind: "error"; readonly link: string; readonly error: InviteError };

/** How long typing has to pause before the link is checked. */
export const CHECK_DELAY_MS = 350;

export function NewAccountFlow({
  onBack,
  onFinish,
}: {
  readonly onBack: () => void;
  /** The folder is created; the caller shows "All set". */
  readonly onFinish: (path: string) => Promise<void>;
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [link, setLink] = useState("");
  const [deviceName, setDeviceName] = useState<string | null>(null);
  const [code, setCode] = useState<RecoveryCode | null>(null);
  const titleId = useId();

  if (step === 2 && code) {
    return (
      <RecoveryCodeStep
        code={code}
        titleId={titleId}
        step={<StepIndicator step={2} total={3} />}
        secondary={
          <BackButton
            onClick={() => {
              setStep(1);
            }}
          />
        }
        onConfirmed={() => {
          setStep(3);
        }}
      />
    );
  }
  if (step === 3) return <FolderStep titleId={titleId} onFinish={onFinish} />;
  return (
    <ConnectStep
      titleId={titleId}
      link={link}
      onLink={setLink}
      deviceName={deviceName}
      onDeviceName={setDeviceName}
      onBack={onBack}
      onNext={(recovery) => {
        setCode(recovery);
        setStep(2);
      }}
    />
  );
}

function BackButton({ onClick }: { readonly onClick: () => void }) {
  const t = useT();
  return (
    <button type="button" className="button secondary" onClick={onClick}>
      {t("setup.back")}
    </button>
  );
}

function ConnectStep({
  titleId,
  link,
  onLink,
  deviceName,
  onDeviceName,
  onBack,
  onNext,
}: {
  readonly titleId: string;
  readonly link: string;
  readonly onLink: (link: string) => void;
  readonly deviceName: string | null;
  readonly onDeviceName: (name: string) => void;
  readonly onBack: () => void;
  readonly onNext: (code: RecoveryCode) => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [check, setCheck] = useState<Check>({ kind: "idle" });
  const [defaultName] = useLoad(() => backend.defaultDeviceName(), [backend]);
  const action = useAction();
  const name = deviceName ?? (defaultName.status === "ready" ? defaultName.data : "");
  const trimmed = link.trim();

  // Checks the invite once typing pauses; a newer link makes older answers irrelevant.
  useEffect(() => {
    if (trimmed === "") return;
    let current = true;
    const timer = setTimeout(() => {
      if (current) setCheck({ kind: "checking", link: trimmed });
      backend.checkInvite(trimmed).then(
        (result) => {
          if (!current) return;
          setCheck(
            result.ok
              ? { kind: "ok", link: trimmed, host: result.value.host }
              : { kind: "error", link: trimmed, error: result.error },
          );
        },
        (error: unknown) => {
          if (current) {
            setCheck({ kind: "idle" });
            console.error("Hangar Drive: invite check failed", error);
          }
        },
      );
    }, CHECK_DELAY_MS);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [backend, trimmed]);

  const state: Check =
    trimmed === "" || ("link" in check && check.link !== trimmed) ? { kind: "idle" } : check;
  const [refused, setRefused] = useState<NameError | null>(null);
  const ready = state.kind === "ok" && nameProblem(name) === null;

  return (
    <form
      className="step-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready) return;
        void action.run(async () => {
          const result = await backend.beginAccount(trimmed, cleanName(name));
          if (result.ok) onNext(result.value);
          else if (result.error === "blank" || result.error === "edgeWhitespace") {
            setRefused(result.error);
          } else setCheck({ kind: "error", link: trimmed, error: result.error });
        });
      }}
    >
      <StepIndicator step={1} total={3} />
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("setup.connect.title")}
      </h1>
      <p className="step-body">{t("setup.connect.body")}</p>
      <LinkField
        label={t("setup.connect.label")}
        value={link}
        onChange={onLink}
        autoFocus
        placeholder="https://drive.example.org/join#…"
        error={state.kind === "error" ? inviteErrorText(state.error, t) : null}
        status={
          state.kind === "checking" ? (
            <p className="field-help">{t("setup.connect.checking")}</p>
          ) : state.kind === "ok" ? (
            <p className="field-help ok-text">
              <CheckIcon size={16} />
              {t("setup.connect.ok", { host: state.host })}
            </p>
          ) : null
        }
      />
      {state.kind === "ok" && (
        <DeviceNameField
          value={name}
          refused={refused}
          onChange={(value) => {
            setRefused(null);
            onDeviceName(value);
          }}
        />
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <BackButton onClick={onBack} />
        <button type="submit" className="button primary" aria-disabled={!ready || action.pending}>
          {t("setup.next")}
        </button>
      </div>
    </form>
  );
}

function FolderStep({
  titleId,
  onFinish,
}: {
  readonly titleId: string;
  readonly onFinish: (path: string) => Promise<void>;
}) {
  const t = useT();
  const backend = useBackend();
  const [place] = useLoad(() => backend.defaultFolderPlace(), [backend]);
  const [picked, setPicked] = useState<FolderPlace | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const action = useAction();
  const current = picked ?? (place.status === "ready" ? place.data : null);
  const [existing] = useLoad(
    () => (current ? backend.countLocalFiles(current.path) : Promise.resolve(0)),
    [backend, current?.path],
  );

  return (
    <div className="step-form">
      <StepIndicator step={3} total={3} />
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("folder.setup.title")}
      </h1>
      {place.status === "failed" && <Feedback tone="error">{errorText(place.error, t)}</Feedback>}
      {!current ? (
        <Loading />
      ) : (
        <div className="place-card">
          <span className="place-icon">
            <FolderIcon size={28} />
          </span>
          <span className="place-text">
            <span className="place-name">{current.name}</span>
            <PathText path={current.path} className="place-path" />
          </span>
          <button
            type="button"
            className="button secondary"
            disabled={action.pending}
            onClick={() => {
              setMessage(null);
              void action.run(async () => {
                const result = await backend.pickFolder({ kind: "new" });
                if (result.kind === "picked") setPicked({ path: result.path, name: result.name });
                if (result.kind === "refused")
                  setMessage(folderRefusalText(result.reason, result.folder, t));
              });
            }}
          >
            {t("folder.setup.change")}
          </button>
        </div>
      )}
      {message && <Feedback tone="error">{message}</Feedback>}
      <p className="step-body">
        {existing.status === "ready" && existing.data > 0
          ? t("folder.setup.existing", { count: existing.data })
          : t("folder.setup.body")}
      </p>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <span />
        <button
          type="button"
          className="button primary"
          data-autofocus
          aria-disabled={!current || action.pending}
          onClick={() => {
            if (!current) return;
            void action.run(() => onFinish(current.path));
          }}
        >
          {t("setup.done")}
        </button>
      </div>
    </div>
  );
}
