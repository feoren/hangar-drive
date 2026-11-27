// Which dialog of the main window is open. One at a time; every view opens the next one through
// `open`, so the window has one place that knows what is on screen.

import type { Folder, Warning } from "../backend/types";

export type OpenDialog =
  | { readonly kind: "devices" }
  | { readonly kind: "activity" }
  | { readonly kind: "settings" }
  | { readonly kind: "help" }
  | {
      readonly kind: "restore";
      readonly folderId: string;
      readonly tab: "versions" | "trash";
      /** Preselected entry (suspected attack) or a file to filter by. */
      readonly entryId?: string;
      readonly path?: string;
      /** Label of the preselected entry ("Before the changes from ..."). */
      readonly beforeDevice?: string;
    }
  | { readonly kind: "conflicts" }
  | { readonly kind: "names" }
  | {
      readonly kind: "massDelete";
      /** This device's deletes, or another device's that wait here (one dialog, two variants). */
      readonly warning: Extract<Warning, { kind: "massDelete" | "incomingDelete" }>;
      /** Opened by the window itself, so closing it puts the focus on the banner. */
      readonly auto?: boolean;
    }
  | {
      readonly kind: "removedHeads";
      readonly warning: Extract<Warning, { kind: "removedHeads" }>;
      readonly auto?: boolean;
    }
  /** A link the OS handed over to a device that is already set up. */
  | { readonly kind: "linkNotNeeded" }
  | { readonly kind: "stopFolder"; readonly folder: Folder }
  | { readonly kind: "folderNumber"; readonly folder: Folder }
  | { readonly kind: "notSynced"; readonly folder: Folder }
  | { readonly kind: "addFolder" }
  /** `link`: a pairing link the OS handed over, filled in. */
  | { readonly kind: "serverScan"; readonly link?: string }
  | { readonly kind: "serverCompare" }
  | { readonly kind: "reanchor"; readonly folderId: string; readonly folderName: string }
  | { readonly kind: "suspect"; readonly warning: Extract<Warning, { kind: "suspect" }> }
  | { readonly kind: "notMe" }
  /** A new recovery code, from the banner of an account without a valid one. */
  | { readonly kind: "renewRecovery" }
  | { readonly kind: "repair"; readonly link?: string };

export type Open = (dialog: OpenDialog) => void;
