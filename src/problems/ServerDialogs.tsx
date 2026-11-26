// "Your server identifies itself differently" (UX 8.3): exactly two ways back, never a button that
// accepts an unknown key. Either the code of another device of this account, or the server number
// compared with the operator, with the confirm button held back for a second.

import { useId, useState } from "react";

import { useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { ArmedButton, Feedback, Loading, NumberRows } from "../ui/parts";
import { errorText, useAction, useLoad } from "../ui/useAsync";
import { LinkField } from "../setup/LinkField";

export function ServerScanDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const action = useAction();
  const [link, setLink] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = (value: string) => {
    setError(null);
    void action.run(async () => {
      const result = await backend.fixServerWithOffer(value);
      if (result.ok) {
        setDone(true);
        return;
      }
      setError(
        result.error === "otherAccount"
          ? t("error.server.otherAccount")
          : result.error === "expired"
            ? t("error.pair.expired")
            : t("error.pair.notALink"),
      );
    });
  };

  return (
    <Dialog labelledBy={titleId} onClose={onClose} closeOnOutside={false}>
      <h2 id={titleId} className="dialog-title">
        {t("server.fix.scan")}
      </h2>
      {done ? (
        <>
          <Feedback>{t("server.fix.done")}</Feedback>
          <div className="dialog-actions">
            <button type="button" className="button primary" data-autofocus onClick={onClose}>
              {t("common.close")}
            </button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            submit(link);
          }}
        >
          <p className="dialog-body">{t("server.fix.scanBody", { app: t("app.name") })}</p>
          <LinkField
            label={t("pair.new.label")}
            value={link}
            onChange={(value) => {
              setLink(value);
              setError(null);
            }}
            onScanned={submit}
            error={error}
            placeholder="hangar-drive://pair#…"
          />
          {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
          <div className="dialog-actions">
            <button type="button" className="button secondary" onClick={onClose}>
              {t("common.cancel")}
            </button>
            <button
              type="submit"
              className="button primary"
              aria-disabled={link.trim() === "" || action.pending}
            >
              {t("server.fix.apply")}
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

export function ServerCompareDialog({ onClose }: { readonly onClose: () => void }) {
  const t = useT();
  const backend = useBackend();
  const titleId = useId();
  const action = useAction();
  const [loaded] = useLoad(() => backend.getServerNumber(), [backend]);
  const [answer, setAnswer] = useState<"no" | "yes" | null>(null);

  return (
    <Dialog labelledBy={titleId} onClose={onClose} closeOnOutside={false} role="alertdialog">
      <h2 id={titleId} className="dialog-title">
        {t("server.fix.compareTitle")}
      </h2>
      {loaded.status === "loading" && <Loading />}
      {loaded.status === "failed" && <Feedback tone="error">{errorText(loaded.error, t)}</Feedback>}
      {answer === "no" && (
        <>
          <Feedback tone="info">{t("server.fix.mismatch")}</Feedback>
          <div className="dialog-actions">
            <button type="button" className="button primary" data-autofocus onClick={onClose}>
              {t("common.close")}
            </button>
          </div>
        </>
      )}
      {answer === "yes" && (
        <>
          <Feedback>{t("server.fix.done")}</Feedback>
          <div className="dialog-actions">
            <button type="button" className="button primary" data-autofocus onClick={onClose}>
              {t("common.close")}
            </button>
          </div>
        </>
      )}
      {answer === null && loaded.status === "ready" && (
        <>
          <CommandText
            text={t("server.fix.compareBody", { command: "\u0000" })}
            command={loaded.data.command}
          />
          <NumberRows rows={loaded.data.number} label={t("server.number.label")} />
          {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
          <div className="dialog-actions">
            <button
              type="button"
              className="button secondary"
              data-autofocus
              onClick={() => {
                setAnswer("no");
              }}
            >
              {t("server.fix.no")}
            </button>
            <ArmedButton
              armKey={loaded.data.number.groups.join("")}
              onClick={() => {
                void action.run(async () => {
                  await backend.confirmServerNumber();
                  setAnswer("yes");
                });
              }}
            >
              {t("server.fix.yes")}
            </ArmedButton>
          </div>
        </>
      )}
    </Dialog>
  );
}

/** The sentence with the command set apart in the monospace face, so it can be read out exactly. */
function CommandText({ text, command }: { readonly text: string; readonly command: string }) {
  const [before = "", after = ""] = text.split("\u0000");
  return (
    <p className="dialog-body">
      {before}
      <code className="command">{command}</code>
      {after}
    </p>
  );
}
