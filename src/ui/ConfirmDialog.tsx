// A question with one sentence or two, one recommended button and one alternative (UX 1.4).
// The button that loses nothing gets the focus.

import { useId, type ReactNode } from "react";

import { useT } from "../i18n";
import { Dialog } from "./Dialog";
import { Feedback } from "./parts";
import { errorText, useAction } from "./useAsync";

interface Props {
  readonly title: string;
  readonly children: ReactNode;
  readonly confirmLabel: string;
  /** Danger style for the confirm button (deleting, removing). */
  readonly danger?: boolean;
  /** Which button has the focus: the safe one by default. */
  readonly focus?: "cancel" | "confirm";
  readonly cancelLabel?: string;
  readonly onConfirm: () => Promise<void>;
  readonly onClose: () => void;
  /** Runs after a successful confirm instead of closing (a dialog that leads to a next step). */
  readonly onConfirmed?: () => void;
}

export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger = false,
  focus = "cancel",
  cancelLabel,
  onConfirm,
  onClose,
  onConfirmed,
}: Props) {
  const t = useT();
  const titleId = useId();
  const bodyId = useId();
  const action = useAction();
  return (
    <Dialog labelledBy={titleId} describedBy={bodyId} onClose={onClose} role="alertdialog">
      <h2 id={titleId} className="dialog-title">
        {title}
      </h2>
      <div id={bodyId} className="dialog-body">
        {children}
      </div>
      {action.error !== null && <Feedback tone="error">{errorText(action.error, t)}</Feedback>}
      <div className="dialog-actions">
        <button
          type="button"
          className="button secondary"
          data-autofocus={focus === "cancel" ? true : undefined}
          onClick={onClose}
        >
          {cancelLabel ?? t("common.cancel")}
        </button>
        <button
          type="button"
          className={danger ? "button danger" : "button primary"}
          data-autofocus={focus === "confirm" ? true : undefined}
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              await onConfirm();
              if (onConfirmed) onConfirmed();
              else onClose();
            });
          }}
        >
          {confirmLabel}
        </button>
      </div>
    </Dialog>
  );
}
