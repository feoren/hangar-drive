// Which dialog of the main window is open. One at a time; every view opens the next one through
// `open`, so the window has one place that knows what is on screen.

import type { Folder, Warning } from "../backend/types";

export type OpenDialog =
  | { readonly kind: "devices" }
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
  | { readonly kind: "massDelete"; readonly warning: Extract<Warning, { kind: "massDelete" }> }
  | { readonly kind: "stopFolder"; readonly folder: Folder }
  | { readonly kind: "deleteFolder"; readonly folder: Folder }
  | { readonly kind: "folderNumber"; readonly folder: Folder }
  | { readonly kind: "notSynced"; readonly folder: Folder }
  | { readonly kind: "addFolder" }
  | { readonly kind: "serverScan" }
  | { readonly kind: "serverCompare" }
  | { readonly kind: "reanchor"; readonly folderId: string; readonly folderName: string }
  | { readonly kind: "suspect"; readonly warning: Extract<Warning, { kind: "suspect" }> }
  | { readonly kind: "notMe" }
  | { readonly kind: "repair" };

export type Open = (dialog: OpenDialog) => void;
