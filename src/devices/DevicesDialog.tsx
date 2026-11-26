// Devices (UX 10): the person's devices, adding one, removing one, the recovery code row.

import { useId, useRef, useState } from "react";

import type { Device, DeviceList, NameError } from "../backend/types";
import { cleanName, nameProblem } from "../domain/names";
import { nameErrorText } from "../setup/common";
import { formatDate, formatRelative } from "../format";
import { useLanguage, useT } from "../i18n";
import { useBackend, useNow } from "../ui/backendContext";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Dialog } from "../ui/Dialog";
import { DesktopIcon, LaptopIcon, PlusIcon } from "../ui/icons";
import { RowMenu } from "../ui/Menu";
import { Feedback, Loading, NumberRows } from "../ui/parts";
import { isMenuKey, useRoving } from "../ui/roving";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { RecoveryCodeStep } from "../setup/RecoveryCodeStep";
import { AddDeviceDialog } from "./AddDeviceDialog";

const STALE_MS = 90 * 24 * 60 * 60 * 1000;

type Sub =
  | { readonly kind: "add" }
  | { readonly kind: "rename"; readonly device: Device }
  | { readonly kind: "safety"; readonly device: Device }
  | { readonly kind: "remove"; readonly device: Device }
  | { readonly kind: "disconnect"; readonly lastOne: boolean }
  | { readonly kind: "renew" };

export function DevicesDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const titleId = useId();
  const [list, reload] = useLoad(() => backend.listDevices(), [backend]);
  const [sub, setSub] = useState<Sub | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const closeSub = () => {
    setSub(null);
    reload();
  };

  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      <div className="view-head">
        <h2 id={titleId} className="dialog-title">
          {t("devices.title")}
        </h2>
        <button
          type="button"
          className="button primary with-icon"
          onClick={() => {
            setFeedback(null);
            setSub({ kind: "add" });
          }}
        >
          <PlusIcon size={18} />
          {t("devices.add")}
        </button>
      </div>
      <div className="view-body">
        {feedback && <Feedback>{feedback}</Feedback>}
        {list.status === "loading" && <Loading />}
        {list.status === "failed" && <Feedback tone="error">{errorText(list.error, t)}</Feedback>}
        {list.status === "ready" && (
          <>
            <DeviceRows list={list.data} onOpen={setSub} />
            <div className="recovery-row">
              <span className="recovery-text">
                <span className="row-name">{t("devices.recovery")}</span>
                <span className="row-sub">
                  {t("devices.recovery.created", {
                    date: formatDate(language, list.data.recoveryCreated),
                  })}
                </span>
              </span>
              <button
                type="button"
                className="button secondary small"
                onClick={() => {
                  setFeedback(null);
                  setSub({ kind: "renew" });
                }}
              >
                {t("devices.recovery.renew")}
              </button>
            </div>
          </>
        )}
      </div>
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
      {sub?.kind === "add" && (
        <AddDeviceDialog
          onAdded={(name) => {
            setFeedback(t("pair.added", { device: name }));
          }}
          onClose={closeSub}
        />
      )}
      {sub?.kind === "rename" && <RenameDialog device={sub.device} onClose={closeSub} />}
      {sub?.kind === "safety" && <SafetyDialog device={sub.device} onClose={closeSub} />}
      {sub?.kind === "remove" && (
        <ConfirmDialog
          title={t("devices.remove.title", { device: sub.device.name })}
          confirmLabel={t("devices.remove")}
          danger
          onConfirm={async () => {
            await backend.removeDevice(sub.device.id);
            setFeedback(t("devices.removed", { device: sub.device.name }));
          }}
          onClose={closeSub}
        >
          <p>{t("devices.remove.body", { app: t("app.name") })}</p>
          <p className="muted">{t("devices.remove.lost")}</p>
        </ConfirmDialog>
      )}
      {sub?.kind === "disconnect" && <DisconnectDialog lastOne={sub.lastOne} onClose={closeSub} />}
      {sub?.kind === "renew" && (
        <RenewDialog
          onDone={() => {
            setFeedback(t("devices.recovery.renewed"));
          }}
          onClose={closeSub}
        />
      )}
    </Dialog>
  );
}

function DeviceRows({
  list,
  onOpen,
}: {
  readonly list: DeviceList;
  readonly onOpen: (sub: Sub) => void;
}) {
  const roving = useRoving(list.devices.length);
  const others = list.devices.filter((device) => !device.isThis).length;
  // This device first, then by last seen.
  const sorted = [...list.devices].sort(
    (a, b) => Number(b.isThis) - Number(a.isThis) || (b.lastSeen ?? 0) - (a.lastSeen ?? 0),
  );
  return (
    <div className="list device-list" role="list" onKeyDown={roving.onKeyDown}>
      {sorted.map((device, index) => (
        <DeviceRow
          key={device.id}
          device={device}
          lastOne={others === 0}
          tabIndex={roving.tabIndex(index)}
          onFocus={() => {
            roving.onItemFocus(index);
          }}
          onOpen={onOpen}
        />
      ))}
    </div>
  );
}

function DeviceRow({
  device,
  lastOne,
  tabIndex,
  onFocus,
  onOpen,
}: {
  readonly device: Device;
  readonly lastOne: boolean;
  readonly tabIndex: 0 | -1;
  readonly onFocus: () => void;
  readonly onOpen: (sub: Sub) => void;
}) {
  const t = useT();
  const language = useLanguage();
  const now = useNow();
  const [menuOpen, setMenuOpen] = useState(false);
  const main = useRef<HTMLButtonElement>(null);
  const seen = device.isThis
    ? t("devices.this")
    : device.lastSeen !== null
      ? t("devices.lastSeen", { when: formatRelative(language, device.lastSeen, now) })
      : null;
  const since = t("devices.since", { date: formatDate(language, device.added, now) });
  const stale = !device.isThis && device.lastSeen !== null && now - device.lastSeen > STALE_MS;
  const label = [device.name, seen, since, stale ? t("devices.stale") : null]
    .filter(Boolean)
    .join(", ");

  return (
    <div role="listitem" className={device.isThis ? "row device-row this" : "row device-row"}>
      <div className="row-line">
        <button
          ref={main}
          type="button"
          className="row-main"
          data-roving
          tabIndex={tabIndex}
          aria-label={label}
          onFocus={onFocus}
          onClick={(event) => {
            if (event.detail === 0) setMenuOpen(true);
          }}
          onKeyDown={(event) => {
            if (isMenuKey(event)) {
              event.preventDefault();
              setMenuOpen(true);
            }
          }}
        >
          <span className="row-icon">
            {device.kind === "laptop" ? <LaptopIcon /> : <DesktopIcon />}
          </span>
          <span className="row-text">
            <span className="row-name">{device.name}</span>
            <span className={device.isThis ? "row-sub this-device" : "row-sub"}>{seen}</span>
          </span>
          <span className="row-status">{since}</span>
        </button>
        <RowMenu
          items={[
            {
              id: "rename",
              label: t("devices.rename"),
              onSelect: () => {
                onOpen({ kind: "rename", device });
              },
            },
            {
              id: "safety",
              label: t("devices.showSafety"),
              onSelect: () => {
                onOpen({ kind: "safety", device });
              },
            },
            device.isThis
              ? {
                  id: "disconnect",
                  label: t("devices.disconnect"),
                  danger: true,
                  separated: true,
                  onSelect: () => {
                    onOpen({ kind: "disconnect", lastOne });
                  },
                }
              : {
                  id: "remove",
                  label: t("devices.remove"),
                  danger: true,
                  separated: true,
                  onSelect: () => {
                    onOpen({ kind: "remove", device });
                  },
                },
          ]}
          label={t("main.rowMenu", { name: device.name })}
          open={menuOpen}
          onOpenChange={setMenuOpen}
          returnFocus={main}
        />
      </div>
      {stale && <p className="row-note">{t("devices.stale")}</p>}
    </div>
  );
}

function RenameDialog({
  device,
  onClose,
}: {
  readonly device: Device;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const inputId = useId();
  const [name, setName] = useState(device.name);
  const action = useAction();
  const [refused, setRefused] = useState<NameError | null>(null);
  const problem = nameProblem(name) ?? refused;
  const empty = problem !== null;
  return (
    <Dialog labelledBy={titleId} onClose={onClose} closeOnOutside={false}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (empty) return;
          void action.run(async () => {
            const result = await backend.renameDevice(device.id, cleanName(name));
            if (result.ok) onClose();
            else setRefused(result.error);
          });
        }}
      >
        <h2 id={titleId} className="dialog-title">
          {t("devices.rename.title", { device: device.name })}
        </h2>
        <div className="field">
          <label htmlFor={inputId} className="field-label">
            {t("devices.rename.label")}
          </label>
          <input
            id={inputId}
            className="input"
            value={name}
            maxLength={64}
            data-autofocus
            aria-invalid={empty ? true : undefined}
            onChange={(event) => {
              setRefused(null);
              setName(event.target.value);
            }}
            onFocus={(event) => {
              event.currentTarget.select();
            }}
          />
          {problem && <p className="field-help error-text">{nameErrorText(problem, t)}</p>}
        </div>
        {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="button primary" aria-disabled={empty || action.pending}>
            {t("common.save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function SafetyDialog({
  device,
  onClose,
}: {
  readonly device: Device;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const [loaded] = useLoad(() => backend.getSafetyNumber(device.id), [backend, device.id]);
  return (
    <Dialog labelledBy={titleId} onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("devices.safety.title", { device: device.name })}
      </h2>
      <p className="dialog-body">{t("devices.safety.body")}</p>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {loaded.status === "ready" && <NumberRows rows={loaded.data} label={t("safety.label")} />}
      <div className="dialog-actions">
        <button type="button" className="button primary" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

/** "Disconnect this device" (UX 10.2); the only device needs a second confirmation. */
function DisconnectDialog({
  lastOne,
  onClose,
}: {
  readonly lastOne: boolean;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const [second, setSecond] = useState(false);
  if (lastOne && !second) {
    return (
      <ConfirmDialog
        title={t("devices.disconnect")}
        confirmLabel={t("devices.disconnect")}
        danger
        onConfirm={() => Promise.resolve()}
        onClose={onClose}
        onConfirmed={() => {
          setSecond(true);
        }}
      >
        <p>{t("devices.disconnect.body")}</p>
      </ConfirmDialog>
    );
  }
  return (
    <ConfirmDialog
      key={second ? "second" : "first"}
      title={t("devices.disconnect")}
      confirmLabel={second ? t("devices.lastOne.confirm") : t("devices.disconnect")}
      danger
      onConfirm={() => backend.disconnectThisDevice()}
      onClose={onClose}
    >
      <p>{second ? t("devices.lastOne") : t("devices.disconnect.body")}</p>
    </ConfirmDialog>
  );
}

function RenewDialog({
  onDone,
  onClose,
}: {
  readonly onDone: () => void;
  readonly onClose: () => void;
}) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const [code] = useLoad(() => backend.renewRecoveryCode(), [backend]);
  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose} closeOnOutside={false}>
      {code.status === "loading" && <Loading />}
      {code.status === "failed" && <Feedback tone="error">{errorText(code.error, t)}</Feedback>}
      {code.status === "ready" && (
        <RecoveryCodeStep
          code={code.data}
          titleId={titleId}
          intro={t("devices.recovery.renewBody")}
          secondary={
            <button type="button" className="button secondary" onClick={onClose}>
              {t("common.cancel")}
            </button>
          }
          onConfirmed={() => {
            onDone();
            onClose();
          }}
        />
      )}
    </Dialog>
  );
}
