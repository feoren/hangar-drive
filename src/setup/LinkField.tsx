// The one field for a link (invite or pairing): type or paste, the "Paste" button that reads the
// clipboard only on that click, and the camera when there is one (UX 4.2 step 1, 4.3).

import { useId, useState, type ReactNode } from "react";

import { useT } from "../i18n";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { errorText, useAction } from "../ui/useAsync";

interface Props {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  /** A link from the clipboard or the camera, ready to check at once. */
  readonly onScanned?: (value: string) => void;
  readonly error: string | null;
  /** A line under the field while there is no error (checking, connected). */
  readonly status?: ReactNode;
  readonly placeholder?: string;
  readonly autoFocus?: boolean;
}

export function LinkField({
  label,
  value,
  onChange,
  onScanned,
  error,
  status,
  placeholder,
  autoFocus,
}: Props) {
  const t = useT();
  const backend = useBackend();
  const camera = useSnapshot().env.camera;
  const inputId = useId();
  const messageId = useId();
  const action = useAction();
  const [note, setNote] = useState<string | null>(null);
  const shown = error ?? note ?? (action.error !== null ? errorText(action.error, t) : null);

  const take = (text: string) => {
    const clean = text.trim();
    onChange(clean);
    onScanned?.(clean);
  };

  return (
    <div className="field">
      <label htmlFor={inputId} className="field-label">
        {label}
      </label>
      <div className="field-row">
        <input
          id={inputId}
          className="input mono-input"
          value={value}
          placeholder={placeholder}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          inputMode="url"
          data-autofocus={autoFocus ? true : undefined}
          autoFocus={autoFocus}
          aria-invalid={error ? true : undefined}
          aria-describedby={messageId}
          onChange={(event) => {
            setNote(null);
            onChange(event.target.value);
          }}
        />
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            setNote(null);
            void action.run(async () => {
              const text = await backend.readClipboardText();
              if (text.trim() === "") setNote(t("setup.pasteEmpty"));
              else take(text);
            });
          }}
        >
          {t("setup.connect.paste")}
        </button>
      </div>
      <div id={messageId} className="field-message" aria-live="polite">
        {shown ? <p className="field-help error-text">{shown}</p> : status}
      </div>
      {camera && (
        <button
          type="button"
          className="button secondary"
          disabled={action.pending}
          onClick={() => {
            void action.run(async () => {
              const scanned = await backend.scanWithCamera();
              if (scanned) take(scanned);
            });
          }}
        >
          {t("setup.connect.scan")}
        </button>
      )}
    </div>
  );
}
