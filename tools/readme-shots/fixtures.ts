// The mock backend's example data in English, for the README screenshots only: run.mjs serves this
// module in place of src/backend/mock/fixtures.ts, with the same exports, so the real mock backend
// (src/backend/mock/mockBackend.ts) runs unchanged on made-up English names. Every name, path and
// host in it is invented. Times are relative to `now`, as in the original.

import type {
  ActivityEntry,
  ConflictGroup,
  Device,
  Folder,
  Millis,
  NameIssue,
  NotSyncedEntry,
  NumberRows,
  QrMatrix,
  TimelineEntry,
  TrashItem,
  TreeNode,
} from "../../src/backend/types";

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

export const HOST: string = "drive.example.org";
export const HOME: string = "C:\\Users\\sam";

export const THIS_DEVICE: string = "Work laptop";
export const OTHER_DEVICE: string = "Office PC";
/** A device this account removed; its changes stop a folder in the "removedHeads" scenario. */
export const REMOVED_DEVICE: string = "Old laptop";

/** IDs of the example account, lowercase hex as the backend sends them. */
export const ACCOUNT: string = "3f9a12c08b7e44d1a0b2c3d4e5f60718";
export const SERVER_ID: string = "9c41d07e2ab35f68c1e0d4b7a3925f16";
export const GENESIS: string = "e7b2049c55a1d3f8b6c0e91a24d7f35c8b19a6e0d2c4f7a3b5e8d1c6f0a9b2e4";
/** The account behind the pairing link "...#stranger": an account the person does not know. */
export const STRANGER_ACCOUNT: string = "c0ffee00d15ea5e0ba5eba11deadbeef";

/** Devices of that unknown account, as this device sees them right after joining. */
export function strangerDevices(now: Millis): Device[] {
  return [
    { id: "d-this", name: THIS_DEVICE, kind: "laptop", isThis: true, lastSeen: now, added: now },
    {
      id: "d-x1",
      name: "DESKTOP-7Q2KF0M",
      kind: "desktop",
      isThis: false,
      lastSeen: now - 2 * HOUR,
      added: now - 3 * DAY,
    },
  ];
}

export function folders(): Folder[] {
  return [
    {
      id: "f-main",
      name: "Documents",
      path: `${HOME}\\Documents`,
      status: { kind: "upToDate" },
      freezeDays: null,
      notSyncedCount: 0,
      bytes: 2_412_000_000,
      fileCount: 1_234,
    },
    {
      id: "f-photos",
      name: "Photos",
      path: "D:\\Photos",
      status: { kind: "upToDate" },
      freezeDays: null,
      notSyncedCount: 0,
      bytes: 86_300_000_000,
      fileCount: 18_406,
    },
    {
      id: "f-projects",
      name: "Projects",
      path: `${HOME}\\Projects`,
      status: { kind: "upToDate" },
      freezeDays: null,
      notSyncedCount: 0,
      bytes: 7_840_000_000,
      fileCount: 5_912,
    },
    {
      id: "f-music",
      name: "Music",
      path: "D:\\Music",
      status: { kind: "upToDate" },
      freezeDays: null,
      notSyncedCount: 0,
      bytes: 31_600_000_000,
      fileCount: 4_870,
    },
  ];
}

export function activity(now: Millis): ActivityEntry[] {
  return [
    {
      kind: "file",
      id: "a1",
      folderId: "f-main",
      folderName: "Documents",
      name: "Report.docx",
      path: "Projects/Report.docx",
      action: "changed",
      device: null,
      at: now - 2 * MINUTE,
    },
    {
      kind: "file",
      id: "a2",
      folderId: "f-photos",
      folderName: "Photos",
      name: "Holiday 014.jpg",
      path: "Holiday/Holiday 014.jpg",
      action: "fromDevice",
      device: OTHER_DEVICE,
      at: now - 62 * MINUTE,
    },
    {
      kind: "group",
      id: "a3",
      folderId: "f-photos",
      folderName: "Photos",
      count: 120,
      at: now - 3 * HOUR,
    },
    {
      kind: "file",
      id: "a4",
      folderId: "f-main",
      folderName: "Documents",
      name: "Quote Harbor Bakery.pdf",
      path: "Clients/Quote Harbor Bakery.pdf",
      action: "restored",
      device: null,
      at: now - 5 * HOUR,
    },
    {
      kind: "file",
      id: "a5",
      folderId: "f-main",
      folderName: "Documents",
      name: "Notes.txt",
      path: "Notes.txt",
      action: "deleted",
      device: null,
      at: now - DAY - 2 * HOUR,
    },
    {
      kind: "remoteDeleted",
      id: "a6",
      folderId: "f-photos",
      folderName: "Photos",
      count: 14,
      device: OTHER_DEVICE,
      at: now - DAY - 4 * HOUR,
    },
    {
      kind: "file",
      id: "a7",
      folderId: "f-main",
      folderName: "Documents",
      name: "Plan 2027.xlsx",
      path: "Projects/Plan 2027.xlsx",
      action: "renamed",
      device: null,
      at: now - 3 * DAY,
    },
  ];
}

export function devices(now: Millis): Device[] {
  return [
    {
      id: "d-this",
      name: THIS_DEVICE,
      kind: "laptop",
      isThis: true,
      lastSeen: now,
      added: now - 30 * DAY,
    },
    {
      id: "d-office",
      name: OTHER_DEVICE,
      kind: "desktop",
      isThis: false,
      lastSeen: now - 5 * MINUTE,
      added: now - 54 * DAY,
    },
    {
      id: "d-old",
      name: REMOVED_DEVICE,
      kind: "laptop",
      isThis: false,
      lastSeen: now - 104 * DAY,
      added: now - 400 * DAY,
    },
  ];
}

export function conflicts(now: Millis): ConflictGroup[] {
  return [
    {
      id: "c1",
      folderId: "f-main",
      folderName: "Documents",
      path: "Projects",
      kind: "content",
      versions: [
        {
          id: "c1-a",
          name: "Report.docx",
          device: OTHER_DEVICE,
          modified: now - 40 * MINUTE,
          size: 48_200,
          original: true,
        },
        {
          id: "c1-b",
          name: `Report (conflict ${THIS_DEVICE} 2026-11-27).docx`,
          device: THIS_DEVICE,
          modified: now - 35 * MINUTE,
          size: 51_900,
          original: false,
        },
      ],
    },
    {
      id: "c2",
      folderId: "f-photos",
      folderName: "Photos",
      path: "Holiday",
      kind: "caseOnly",
      versions: [
        {
          id: "c2-a",
          name: "Beach.JPG",
          device: OTHER_DEVICE,
          modified: now - 2 * DAY,
          size: 3_400_000,
          original: true,
        },
        {
          id: "c2-b",
          name: "beach.jpg",
          device: THIS_DEVICE,
          modified: now - 2 * DAY + 20 * MINUTE,
          size: 3_350_000,
          original: false,
        },
      ],
    },
  ];
}

export function nameIssues(): NameIssue[] {
  return [
    {
      id: "n1",
      folderId: "f-main",
      folderName: "Documents",
      dir: "Projects",
      name: "Budget: Q1.xlsx",
      reason: { kind: "char", char: ":" },
      device: "MacBook",
    },
    {
      id: "n2",
      folderId: "f-main",
      folderName: "Documents",
      dir: "",
      name: "CON.txt",
      reason: { kind: "reserved", name: "CON" },
      device: "MacBook",
    },
    {
      id: "n3",
      folderId: "f-photos",
      folderName: "Photos",
      dir: "Holiday",
      name: "Notes.",
      reason: { kind: "trailing" },
      device: "MacBook",
    },
    {
      id: "n4",
      folderId: "f-photos",
      folderName: "Photos",
      dir: "",
      name: "New",
      reason: { kind: "cannotCreate" },
      device: OTHER_DEVICE,
    },
  ];
}

export function notSynced(): NotSyncedEntry[] {
  return [
    { path: "Projects\\Shortcut to server.lnk", reason: "link" },
    { path: "Projects\\Archive", reason: "link" },
    { path: "desktop.ini", reason: "system" },
  ];
}

export function timeline(now: Millis, folderId: string): TimelineEntry[] {
  const other = folderId === "f-photos" ? "Old laptop" : OTHER_DEVICE;
  return [
    {
      id: "t1",
      at: now - 25 * MINUTE,
      device: THIS_DEVICE,
      changed: 3,
      added: 0,
      deleted: 0,
      reanchored: false,
    },
    {
      id: "t2",
      at: now - 3 * HOUR,
      device: other,
      changed: 0,
      added: 12,
      deleted: 0,
      reanchored: false,
    },
    {
      id: "t3",
      at: now - 5 * HOUR,
      device: THIS_DEVICE,
      changed: 1,
      added: 1,
      deleted: 0,
      reanchored: false,
    },
    {
      id: "t4",
      at: now - DAY - 6 * HOUR,
      device: other,
      changed: 0,
      added: 0,
      deleted: 1,
      reanchored: false,
    },
  ];
}

/** The tree of one version; older versions differ more from now. */
export function tree(entryId: string): TreeNode[] {
  const age = Number(entryId.slice(1)) || 1;
  const nodes: TreeNode[] = [
    { path: "Projects", name: "Projects", depth: 0, kind: "dir", diff: "same" },
    {
      path: "Projects/Report.docx",
      name: "Report.docx",
      depth: 1,
      kind: "file",
      diff: "different",
    },
    { path: "Projects/Plan.xlsx", name: "Plan.xlsx", depth: 1, kind: "file", diff: "same" },
    {
      path: "Projects/Sketch.png",
      name: "Sketch.png",
      depth: 1,
      kind: "file",
      diff: age > 2 ? "different" : "same",
    },
    { path: "Clients", name: "Clients", depth: 0, kind: "dir", diff: "same" },
    {
      path: "Clients/Quote Harbor Bakery.pdf",
      name: "Quote Harbor Bakery.pdf",
      depth: 1,
      kind: "file",
      diff: age > 3 ? "missing" : "same",
    },
    { path: "Clients/Contract.pdf", name: "Contract.pdf", depth: 1, kind: "file", diff: "same" },
    { path: "Notes.txt", name: "Notes.txt", depth: 0, kind: "file", diff: "missing" },
    {
      path: "Shopping.md",
      name: "Shopping.md",
      depth: 0,
      kind: "file",
      diff: age > 1 ? "newer" : "same",
    },
  ];
  return nodes;
}

export function trash(now: Millis): TrashItem[] {
  return [
    {
      id: "x1",
      name: "Notes.txt",
      dir: "",
      deletedAt: now - DAY - 2 * HOUR,
      device: THIS_DEVICE,
    },
    { id: "x2", name: "Old.pdf", dir: "Projects", deletedAt: now - 6 * DAY, device: OTHER_DEVICE },
    {
      id: "x3",
      name: "Draft 3.docx",
      dir: "Projects/Drafts",
      deletedAt: now - 9 * DAY,
      device: OTHER_DEVICE,
    },
    {
      id: "x4",
      name: "Invoice 2025-11.pdf",
      dir: "Clients",
      deletedAt: now - 15 * DAY,
      device: THIS_DEVICE,
    },
  ];
}

export function massDeleteList(count: number): string[] {
  return Array.from(
    { length: count },
    (_, i) => `Holiday/Holiday ${String(i + 1).padStart(3, "0")}.jpg`,
  );
}

const CROCKFORD: string = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** A fresh recovery code: 32 characters, the first one `D` like every Drive code. */
export function recoveryCode(random: () => number): string[] {
  const chars = ["D"];
  while (chars.length < 32) chars.push(CROCKFORD[Math.floor(random() * 32)] ?? "0");
  const groups: string[] = [];
  for (let i = 0; i < 32; i += 4) groups.push(chars.slice(i, i + 4).join(""));
  return groups;
}

export function numberRows(seed: number): NumberRows {
  const groups: string[] = [];
  let value = seed;
  for (let i = 0; i < 6; i += 1) {
    value = (value * 48271 + 12345) % 2147483647;
    groups.push(String(value % 100000).padStart(5, "0"));
  }
  return { groups };
}

/** A matrix as the SVG document the engine sends next to it (`PairingOffer.qrSvg`). */
export function qrSvg(matrix: QrMatrix): string {
  const quiet = 4;
  const full = matrix.size + quiet * 2;
  let d = "";
  for (let y = 0; y < matrix.size; y += 1) {
    for (let x = 0; x < matrix.size; x += 1) {
      if (matrix.modules[y * matrix.size + x] === "1") {
        d += `M${String(x + quiet)} ${String(y + quiet)}h1v1h-1z`;
      }
    }
  }
  const box = String(full);
  return (
    `<?xml version="1.0" standalone="yes"?>` +
    `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="${box}" height="${box}" ` +
    `viewBox="0 0 ${box} ${box}" shape-rendering="crispEdges">` +
    `<rect width="${box}" height="${box}" fill="#ffffff"/><path d="${d}" fill="#000000"/></svg>`
  );
}

/** A pattern that looks like a QR code (finder patterns, timing, noise); not decodable. */
export function fakeQr(seed: number): QrMatrix {
  const size = 29;
  const cells: boolean[] = [];
  let value = seed;
  const finder = (x: number, y: number, ox: number, oy: number): boolean | null => {
    const dx = x - ox;
    const dy = y - oy;
    if (dx < -1 || dy < -1 || dx > 7 || dy > 7) return null;
    if (dx === -1 || dy === -1 || dx === 7 || dy === 7) return false;
    const ring = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
    return ring !== 2;
  };
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const fixed = finder(x, y, 0, 0) ?? finder(x, y, size - 7, 0) ?? finder(x, y, 0, size - 7);
      if (fixed !== null) {
        cells.push(fixed);
      } else if (x === 6 || y === 6) {
        cells.push((x + y) % 2 === 0);
      } else {
        value = (value * 1103515245 + 12345) % 2147483648;
        cells.push(value % 7 < 3);
      }
    }
  }
  return { size, modules: cells.map((dark) => (dark ? "1" : "0")).join("") };
}
