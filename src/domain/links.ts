// The links of the app (UX 4.2 to 4.4), told apart by their shape only. The backend reads and
// checks the content (`checkInvite`, `inspectLink`); the window only needs to know which kind a
// text is, so one link field can take any of them and send the person to the right place.
//
// | Kind | Forms |
// | --- | --- |
// | invite | `https://<server>[/<base>]/join#<token>[.<server ID>[.<pin>]]`, `hangar-drive://join#<invite>@<server URL>` |
// | pair | `hangar-drive://pair#<offer>` |
// | recover | `hangar-drive://recover#<sheet>` |

import type { LinkKind } from "../backend/types";

const DEEP = /^hangar-drive:\/\/(join|pair|recover)#\S/i;
const INVITE_HTTPS = /^https?:\/\/[^/#?\s]+(?:\/[^#?\s]*)?\/join#\S/i;

/**
 * A link as it should be sent: white space removed everywhere, because a link never contains any
 * and a link copied from a printed sheet or a mail often breaks over lines.
 */
export function cleanLink(text: string): string {
  return text.replace(/\s+/g, "");
}

/** Which kind of link a text is, or null when it is none of the app's links. */
export function linkKind(text: string): LinkKind | null {
  const link = cleanLink(text);
  const deep = DEEP.exec(link);
  if (deep) {
    const kind = (deep[1] ?? "").toLowerCase();
    return kind === "join" ? "invite" : kind === "pair" ? "pair" : "recover";
  }
  return INVITE_HTTPS.test(link) ? "invite" : null;
}

/** An ID in hex as groups of four, so it can be compared group by group ("3f9a 12c0 ..."). */
export function groupHex(id: string): string {
  const clean = id.replace(/\s+/g, "").toLowerCase();
  const groups: string[] = [];
  for (let i = 0; i < clean.length; i += 4) groups.push(clean.slice(i, i + 4));
  return groups.join(" ");
}
