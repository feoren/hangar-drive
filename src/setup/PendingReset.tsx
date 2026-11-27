// Resetting while a recovery is pending (follow-up review LOW 7): this device's new key may be
// the account's only one, so the window says what is at stake before it offers the reset. The
// shell asks once more natively, "no" as its default, before anything is thrown away.

import { useId } from "react";

import { useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { Feedback } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";

export function PendingResetWarning({ onCancel }: { readonly onCancel: () => void }) {
  const t = useT();
  const backend = useBackend();
  const action = useAction();
  const titleId = useId();
  return (
    <div className="notice" role="alert" aria-labelledby={titleId}>
      <p id={titleId} className="notice-title">
        {t("reset.pending.title")}
      </p>
      <p>{t("reset.pending.body")}</p>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="step-actions">
        <button
          type="button"
          className="button secondary"
          data-autofocus
          autoFocus
          onClick={onCancel}
        >
          {t("common.cancel")}
        </button>
        <button
          type="button"
          className="button danger"
          disabled={action.pending}
          onClick={() => {
            // "Confirmed": the next snapshot shows the welcome; "no" in the native question
            // changes nothing and keeps this warning.
            void action.run(async () => {
              await backend.resetDeviceDiscardingRecovery();
            });
          }}
        >
          {t("reset.pending.anyway")}
        </button>
      </div>
    </div>
  );
}
