// The recovery sheet, version 2 (UX 4.2 step 2, 4.4): the code and, in the clear, everything the
// sheet's link carries, plus the plain sentences. The window words it in the person's language;
// the backend only lays it out for printing (with a QR code of the link) or writes a text file.

import type { RecoveryCode, RecoverySheetDocument } from "../backend/types";
import { groupHex } from "../domain/links";
import { formatLongDate } from "../format";
import { LOCALES, type Language, type Translate } from "../i18n";

export function recoverySheetDocument(
  code: RecoveryCode,
  t: Translate,
  language: Language,
  now: number,
  deviceName?: string,
): RecoverySheetDocument {
  const app = t("app.name");
  const sheet = code.sheet;
  const fields: { label: string; value: string }[] = [
    { label: t("recover.codeLabel"), value: code.groups.join(" ") },
    { label: t("pair.check.server"), value: sheet.serverUrl },
    { label: t("sheet.serverId"), value: groupHex(sheet.serverId) },
    { label: t("sheet.accountId"), value: groupHex(sheet.accountId) },
    { label: t("sheet.anchor"), value: groupHex(sheet.genesisAnchor) },
  ];
  if (sheet.pin !== null) fields.push({ label: t("sheet.pin"), value: sheet.pin });
  fields.push(
    { label: t("sheet.link"), value: sheet.link },
    { label: t("sheet.date"), value: formatLongDate(language, now) },
  );
  if (deviceName) fields.push({ label: t("sheet.device"), value: deviceName });
  return {
    language: LOCALES[language],
    title: t("sheet.title", { app }),
    fields,
    notes: [
      t("sheet.note.what"),
      t("sheet.note.access"),
      t("sheet.note.gone"),
      t("sheet.note.how", { app, door: t("welcome.recover") }),
    ],
    qrLink: sheet.link,
    fileName: t("sheet.fileName", { app }),
  };
}
