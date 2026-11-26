// Additional device in two steps (UX 4.3): pair with the other device, then choose the folders.
// Also used for "Pair again" after this device was removed (UX 8.8).
//
// Before a pairing link is sent, the window shows the server (its host in punycode) and the
// account the link leads to and asks once (N2). After joining, it shows the account's devices:
// a link that leads to a stranger's account shows strangers, and "No" disconnects this device
// again before any file moves.

import { useEffect, useId, useRef, useState } from "react";

import type {
  InspectedLink,
  LinkError,
  LinkKind,
  NameError,
  PairError,
  PairInput,
  PairWaiting,
} from "../backend/types";
import { cleanLink, groupHex, linkKind } from "../domain/links";
import { cleanName, nameProblem } from "../domain/names";
import { useT, type Translate } from "../i18n";
import { useBackendEvent } from "../ui/appContext";
import { useBackend } from "../ui/backendContext";
import { DesktopIcon, LaptopIcon } from "../ui/icons";
import { ArmedButton, Feedback, Loading, NumberRows } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { DeviceNameField, FolderChoiceStep, StepIndicator } from "./common";
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

/** Why a link could not be read, for the pairing and the recovery field. */
export function linkErrorText(error: LinkError, notALink: string, t: Translate): string {
  switch (error) {
    case "notALink":
      return notALink;
    case "damaged":
      return t("error.link.damaged");
    case "insecure":
      return t("error.insecure", { app: t("app.name") });
  }
}

type Stage = "pair" | "devices" | "folders";

export function PairFlow({
  titleId,
  initialLink = "",
  onSwitch,
  onBack,
  onDone,
}: {
  readonly titleId?: string;
  /** A pairing link the OS handed over; the server question comes up at once. */
  readonly initialLink?: string;
  readonly onSwitch?: ((kind: LinkKind, link: string) => void) | undefined;
  readonly onBack: () => void;
  readonly onDone: () => void;
}) {
  const ownTitle = useId();
  const title = titleId ?? ownTitle;
  const [stage, setStage] = useState<Stage>("pair");
  const [aborted, setAborted] = useState(false);
  if (stage === "folders") {
    return (
      <FolderChoiceStep
        titleId={title}
        step={<StepIndicator step={2} total={2} />}
        onDone={onDone}
      />
    );
  }
  if (stage === "devices") {
    return (
      <DevicesCheck
        titleId={title}
        onYes={() => {
          setStage("folders");
        }}
        onAborted={() => {
          setAborted(true);
          setStage("pair");
        }}
      />
    );
  }
  return (
    <PairStep
      titleId={title}
      initialLink={aborted ? "" : initialLink}
      aborted={aborted}
      onSwitch={onSwitch}
      onBack={onBack}
      onJoined={() => {
        setStage("devices");
      }}
    />
  );
}

function PairStep({
  titleId,
  initialLink,
  aborted,
  onSwitch,
  onBack,
  onJoined,
}: {
  readonly titleId: string;
  readonly initialLink: string;
  /** The person said "no" to the devices of the last account: say it is undone. */
  readonly aborted: boolean;
  readonly onSwitch: ((kind: LinkKind, link: string) => void) | undefined;
  readonly onBack: () => void;
  readonly onJoined: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const app = t("app.name");
  const [typed, setTyped] = useState(false);
  const [link, setLink] = useState(initialLink);
  const [server, setServer] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [target, setTarget] = useState<{ link: string; info: InspectedLink } | null>(null);
  const [waiting, setWaiting] = useState<PairWaiting | null>(null);
  const [joined, setJoined] = useState(false);
  // The name the other device shows in its question; the OS's name until the person changes it.
  const [defaultName] = useLoad(() => backend.defaultDeviceName(), [backend]);
  const [name, setName] = useState<string | null>(null);
  const [refused, setRefused] = useState<NameError | null>(null);
  const deviceName = name ?? (defaultName.status === "ready" ? defaultName.data : "");
  const nameReady = nameProblem(deviceName) === null;
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
      setTarget(null);
      setError(pairErrorText(event.result.error, t));
    }
  });

  const start = (input: PairInput) => {
    setError(null);
    // A link the OS handed over skips the form; a name that is not ready sends the person there.
    if (!nameReady) {
      setTarget(null);
      return;
    }
    pairing.current = true;
    void action.run(async () => {
      const result = await backend.startPairing(input, cleanName(deviceName));
      if (result.ok) {
        setWaiting((current) => current ?? result.value);
        return;
      }
      pairing.current = false;
      setTarget(null);
      if (result.error === "blank" || result.error === "edgeWhitespace") setRefused(result.error);
      else setError(pairErrorText(result.error, t));
    });
  };

  // N2: a link is read offline first; nothing is sent before the person said yes to its server.
  const inspect = (value: string) => {
    const clean = cleanLink(value);
    setError(null);
    void action.run(async () => {
      const result = await backend.inspectLink(clean);
      if (!result.ok) setError(linkErrorText(result.error, t("error.pair.notALink"), t));
      else if (result.value.kind !== "pair") setError(t("error.pair.notALink"));
      else setTarget({ link: clean, info: result.value });
    });
  };

  // A link the OS handed over goes straight to the question.
  const opened = useRef(false);
  useEffect(() => {
    if (opened.current || linkKind(initialLink) !== "pair") return;
    opened.current = true;
    inspect(initialLink);
    // Runs once for the link the flow was opened with.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
                setTarget(null);
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

  if (target && target.info.kind !== "invite") {
    const info = target.info;
    return (
      <div className="step-form">
        <StepIndicator step={1} total={2} />
        <h1 id={titleId} className="step-title" tabIndex={-1}>
          {t("pair.check.title")}
        </h1>
        <dl className="facts">
          <dt>{t("pair.check.server")}</dt>
          <dd>{info.host}</dd>
          <dt>{t("pair.check.account")}</dt>
          <dd>{groupHex(info.account)}</dd>
        </dl>
        {info.pinned && (
          <div className="notice" role="note">
            <p className="notice-title">{t("setup.connect.pinnedTitle")}</p>
            <p>{t("pair.check.pinned", { app })}</p>
          </div>
        )}
        <p className="step-body">{t("pair.check.body")}</p>
        {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
        <div className="step-actions">
          <button
            type="button"
            className="button secondary"
            data-autofocus
            autoFocus
            onClick={() => {
              setTarget(null);
            }}
          >
            {t("setup.back")}
          </button>
          <ArmedButton
            armKey={`${info.host} ${info.account}`}
            onClick={() => {
              start({ kind: "link", link: target.link });
            }}
          >
            {t("pair.check.connect")}
          </ArmedButton>
        </div>
      </div>
    );
  }

  const clean = cleanLink(link);
  const linkReady = clean !== "" && (linkKind(clean) ?? "pair") === "pair";
  const canStart = nameReady && (typed ? server.trim() !== "" && code.trim() !== "" : linkReady);
  return (
    <form
      className="step-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!canStart || action.pending) return;
        if (typed) start({ kind: "typed", server: server.trim(), code });
        else inspect(clean);
      }}
    >
      <StepIndicator step={1} total={2} />
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("pair.new.title")}
      </h1>
      <p className="step-body">{t("pair.new.body", { app })}</p>
      {aborted && <Feedback tone="info">{t("pair.devices.aborted")}</Feedback>}
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
            expect="pair"
            value={link}
            autoFocus
            placeholder="hangar-drive://pair#…"
            onChange={(value) => {
              setLink(value);
              setError(null);
            }}
            onScanned={inspect}
            onSwitch={onSwitch}
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
      <DeviceNameField
        value={deviceName}
        refused={refused}
        onChange={(next) => {
          setRefused(null);
          setName(next);
        }}
      />
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

/** "Are these your devices?" right after joining, before any folder is chosen (N2). */
function DevicesCheck({
  titleId,
  onYes,
  onAborted,
}: {
  readonly titleId: string;
  readonly onYes: () => void;
  readonly onAborted: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [list] = useLoad(() => backend.listDevices(), [backend]);
  const action = useAction();
  return (
    <div className="step-form">
      <StepIndicator step={1} total={2} />
      <h1 id={titleId} className="step-title" tabIndex={-1}>
        {t("pair.devices.title")}
      </h1>
      <p className="step-body">{t("pair.devices.body")}</p>
      {list.status === "loading" && <Loading />}
      {list.status === "failed" && <Feedback tone="error">{errorText(list.error, t)}</Feedback>}
      {list.status === "ready" && (
        <ul className="device-check" aria-label={t("devices.title")}>
          {list.data.devices.map((device) => (
            <li key={device.id}>
              {device.kind === "laptop" ? <LaptopIcon /> : <DesktopIcon />}
              <span className="row-name">{device.name}</span>
              {device.isThis && <span className="row-sub">{t("devices.this")}</span>}
            </li>
          ))}
        </ul>
      )}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              await backend.disconnectThisDevice();
              onAborted();
            });
          }}
        >
          {t("pair.confirm.no")}
        </button>
        <button
          type="button"
          className="button primary"
          aria-disabled={list.status !== "ready" || action.pending}
          onClick={() => {
            if (list.status === "ready" && !action.pending) onYes();
          }}
        >
          {t("pair.devices.yes")}
        </button>
      </div>
    </div>
  );
}
