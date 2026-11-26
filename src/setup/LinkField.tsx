// The one field for a link (invite, pairing or recovery sheet): type or paste, the "Paste" button
// that reads the clipboard only on that click, and the camera when there is one (UX 4.2 step 1,
// 4.3, 4.4). It knows every link of the app, so a link of another kind is named in words, with a
// button that takes the person where that link belongs.

import { useId, useState, type ReactNode } from "react";

import type { LinkKind } from "../backend/types";
import { cleanLink, linkKind } from "../domain/links";
import { useT, type Translate } from "../i18n";
import { useBackend, useSnapshot } from "../ui/backendContext";
import { errorText, useAction } from "../ui/useAsync";

interface Props {
  readonly label: string;
  /** The kind this field is for; a link of another kind gets a hint instead of being sent. */
  readonly expect: LinkKind;
  readonly value: string;
  readonly onChange: (value: string) => void;
  /** A link from the clipboard or the camera, ready to check at once (only of `expect`). */
  readonly onScanned?: (value: string) => void;
  /** Takes the person to the flow of another kind of link; without it the hint says what fits. */
  readonly onSwitch?: ((kind: LinkKind, link: string) => void) | undefined;
  readonly error: string | null;
  /** A line under the field while there is no error (checking, connected). */
  readonly status?: ReactNode;
  readonly placeholder?: string;
  readonly autoFocus?: boolean;
}

/** The kind of `value` when it is a link of the app, but not of `expect`. */
export function otherKind(value: string, expect: LinkKind): LinkKind | null {
  const kind = linkKind(value);
  return kind !== null && kind !== expect ? kind : null;
}

/**
 * The field's text without white space, as the backend's parsers want it: a link typed in groups
 * of four or pasted over several lines arrives whole. The caret stays after the same character,
 * because the field already shows the cleaned text when React renders it.
 */
export function cleanInput(input: HTMLInputElement): string {
  const raw = input.value;
  const clean = cleanLink(raw);
  if (clean !== raw) {
    const caret = cleanLink(raw.slice(0, input.selectionStart ?? raw.length)).length;
    input.value = clean;
    input.setSelectionRange(caret, caret);
  }
  return clean;
}

function isText(kind: LinkKind, t: Translate): string {
  switch (kind) {
    case "invite":
      return t("link.isInvite");
    case "pair":
      return t("link.isPair");
    case "recover":
      return t("link.isRecover");
  }
}

function switchText(kind: LinkKind, t: Translate): string {
  switch (kind) {
    case "invite":
      return t("link.toInvite");
    case "pair":
      return t("link.toPair");
    case "recover":
      return t("link.toRecover");
  }
}

export function LinkField({
  label,
  expect,
  value,
  onChange,
  onScanned,
  onSwitch,
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
  // "No link on the clipboard" is a quiet note, not a mistake of the person.
  const calm = !error && note !== null && shown === note;
  const other = otherKind(value, expect);

  const take = (text: string) => {
    const clean = cleanLink(text);
    onChange(clean);
    if (otherKind(clean, expect) === null) onScanned?.(clean);
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
          aria-invalid={error || other ? true : undefined}
          aria-describedby={messageId}
          onChange={(event) => {
            setNote(null);
            onChange(cleanInput(event.target));
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
              if (text.trim() === "") setNote(t("setup.pasteNoLink", { app: t("app.name") }));
              else take(text);
            });
          }}
        >
          {t("setup.connect.paste")}
        </button>
      </div>
      <div id={messageId} className="field-message" aria-live="polite">
        {shown ? (
          <p className={calm ? "field-help" : "field-help error-text"}>{shown}</p>
        ) : other ? (
          <p className="field-help">
            {isText(other, t)}{" "}
            {onSwitch ? (
              <button
                type="button"
                className="link-button inline"
                onClick={() => {
                  onSwitch(other, cleanLink(value));
                }}
              >
                {switchText(other, t)}
              </button>
            ) : (
              expect === "pair" && t("link.needPair")
            )}
          </p>
        ) : (
          status
        )}
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
