// Settings (UX 11): only "Start at sign-in" and the language. Below them, not settings but
// information: the account and "About", with the error report and the two honest notes, and
// "Help" with "Reset this device" for starting over.

import { useId, useState } from "react";

import { HANGAR_DRIVE_BUILD } from "../buildInfo";
import { formatSize } from "../format";
import { isLanguage, LANGUAGE_NAMES, LANGUAGES, useLanguage, useT } from "../i18n";
import { formatCombo, FIXED_KEYS, SHORTCUTS } from "../shortcuts";
import { useLanguageSetting } from "../ui/appContext";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { Feedback, Loading } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { formatVersion, withBuild } from "../version";

export function SettingsDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const language = useLanguage();
  const backend = useBackend();
  const snapshot = useSnapshot();
  const setting = useLanguageSetting();
  const titleId = useId();
  const autostartId = useId();
  const autostartHelp = useId();
  const languageId = useId();
  const [settings, reload] = useLoad(() => backend.getSettings(), [backend]);
  const [about] = useLoad(() => backend.getAbout(), [backend]);
  const action = useAction();
  const app = t("app.name");
  const account = snapshot.account;

  return (
    <Dialog labelledBy={titleId} size="medium" onClose={onClose}>
      {/* Focus starts at the top, so the window does not scroll to a control further down. */}
      <h2 id={titleId} className="dialog-title" tabIndex={-1} data-autofocus>
        {t("settings.title")}
      </h2>
      <div className="settings">
        {settings.status === "loading" && <Loading />}
        {settings.status === "failed" && (
          <Feedback tone="error">{errorText(settings.error, t)}</Feedback>
        )}
        {settings.status === "ready" && (
          <section className="settings-group">
            <div className="setting">
              <label className="switch" htmlFor={autostartId}>
                <input
                  id={autostartId}
                  type="checkbox"
                  role="switch"
                  checked={settings.data.autostart}
                  aria-describedby={autostartHelp}
                  disabled={action.pending}
                  onChange={(event) => {
                    const on = event.target.checked;
                    void action.run(async () => {
                      await backend.setAutostart(on);
                      reload();
                    });
                  }}
                />
                <span className="switch-track" aria-hidden="true" />
                <span className="setting-label">{t("settings.autostart")}</span>
              </label>
              <p id={autostartHelp} className="setting-help">
                {t("settings.autostartHelp")}
              </p>
            </div>
            <div className="setting">
              <label htmlFor={languageId} className="setting-label">
                {t("settings.language")}
              </label>
              <select
                id={languageId}
                className="select"
                value={setting.choice}
                onChange={(event) => {
                  const value = event.target.value;
                  if (value === "system" || isLanguage(value)) setting.change(value);
                }}
              >
                <option value="system">{t("settings.languageSystem")}</option>
                {LANGUAGES.map((code) => (
                  <option key={code} value={code} lang={code}>
                    {LANGUAGE_NAMES[code]}
                  </option>
                ))}
              </select>
            </div>
            {action.error !== null && (
              <Feedback tone="error">{errorText(action.error, t)}</Feedback>
            )}
          </section>
        )}

        {account && (
          <section className="settings-group" aria-labelledby={`${titleId}-account`}>
            <h3 id={`${titleId}-account`} className="section-label">
              {t("settings.account")}
            </h3>
            <p className="info-line">{t("settings.server", { host: account.host })}</p>
            {snapshot.storage && (
              <p className="info-line">
                {t("main.storage", {
                  used: formatSize(language, snapshot.storage.used),
                  quota: formatSize(language, snapshot.storage.quota),
                })}
              </p>
            )}
            <p className="info-line">{t("settings.retention", { days: account.retentionDays })}</p>
            {snapshot.notices.map((notice, index) => (
              <p key={`${notice.kind}-${String(index)}`} className="info-line muted">
                {noticeText(notice, t)}
              </p>
            ))}
          </section>
        )}

        <section className="settings-group" aria-labelledby={`${titleId}-about`}>
          <h3 id={`${titleId}-about`} className="section-label">
            {t("settings.about", { app })}
          </h3>
          {about.status === "ready" && (
            <p className="info-line">
              {t("settings.version", {
                // A release build carries its build number in the version (X.Y.Z+B); a
                // development build only gets it from vite.config.ts. Shown as X.Y.Z-B (ADR 0002).
                version: formatVersion(
                  withBuild(about.data.version, about.data.build ?? HANGAR_DRIVE_BUILD),
                ),
              })}
            </p>
          )}
          <p className="info-line">{t("settings.serverNote")}</p>
          <p className="info-line">{t("settings.localNote")}</p>
          <ErrorReport />
        </section>

        <section className="settings-group" aria-labelledby={`${titleId}-help`}>
          <h3 id={`${titleId}-help`} className="section-label">
            {t("help.title")}
          </h3>
          <ResetDevice />
        </section>
      </div>
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}

export function noticeText(
  notice: ReturnType<typeof useSnapshot>["notices"][number],
  t: ReturnType<typeof useT>,
): string {
  switch (notice.kind) {
    case "quota":
      return t("notice.quota");
    case "retained":
      return t("notice.retained");
    case "budgetDevice":
      return t("notice.budgetDevice", { device: notice.device });
    case "budgetAccount":
      return t("notice.budgetAccount");
    case "serverDisk":
      return t("notice.serverDisk");
    case "minCount":
      return t("notice.minCount", { days: notice.days });
    case "olderAccountState":
      return t("notice.olderAccountState", { app: t("app.name") });
  }
}

/** "Save error report": shown before saving, so nobody wonders what leaves the computer. */
function ErrorReport() {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const [preview, setPreview] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  return (
    <div className="report">
      <p className="setting-help">{t("settings.reportHelp")}</p>
      {preview === null ? (
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              setPreview(await backend.previewErrorReport());
            });
          }}
        >
          {t("settings.saveReport")}
        </button>
      ) : (
        <>
          <p className="field-label">{t("settings.reportPreview")}</p>
          <pre className="report-preview" tabIndex={0}>
            {preview}
          </pre>
          <div className="group-actions">
            <button
              type="button"
              className="button secondary"
              onClick={() => {
                setPreview(null);
                setSaved(null);
              }}
            >
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="button primary"
              disabled={action.pending}
              onClick={() => {
                void action.run(async () => {
                  const result = await backend.saveErrorReport();
                  if (result.kind === "saved") setSaved(result.path);
                });
              }}
            >
              {t("common.save")}
            </button>
          </div>
        </>
      )}
      {saved && <Feedback>{t("common.saved", { path: saved })}</Feedback>}
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
    </div>
  );
}

/**
 * "Reset this device": forgets the account here, the files stay. The shell asks natively before
 * it acts (security review M4), so the window asks nothing itself; afterwards the snapshot says
 * the setup is needed and the window shows the welcome. "No" there changes nothing.
 */
function ResetDevice() {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const app = t("app.name");
  return (
    <div className="report">
      <p className="setting-help">{t("reset.help", { app })}</p>
      <button
        type="button"
        className="button secondary"
        disabled={action.pending}
        onClick={() => {
          void action.run(async () => {
            await backend.resetDevice();
          });
        }}
      >
        {t("reset.action")}
      </button>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
    </div>
  );
}

export function HelpDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const titleId = useId();
  const keys = [
    ...SHORTCUTS.map((shortcut) => ({ combo: shortcut.combo, label: shortcut.label })),
    ...FIXED_KEYS,
  ];
  return (
    <Dialog labelledBy={titleId} onClose={onClose}>
      <h2 id={titleId} className="dialog-title">
        {t("help.title")}
      </h2>
      <p className="dialog-body">{t("help.body", { app: t("app.name") })}</p>
      <h3 className="section-label">{t("help.keys")}</h3>
      <dl className="keys">
        {keys.map((entry) => (
          <div key={entry.label} className="key-row">
            <dt>
              <kbd>{formatCombo(entry.combo, t)}</kbd>
            </dt>
            <dd>{t(entry.label)}</dd>
          </div>
        ))}
      </dl>
      <div className="dialog-actions">
        <button type="button" className="button primary" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </Dialog>
  );
}
