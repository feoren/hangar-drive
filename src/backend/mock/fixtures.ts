// Example data for the mock backend: two folders, three devices, a week of history. Times are
// relative to `now`, so the window always shows "2 min ago" and "yesterday" the same way.

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
} from "../types";

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

export const HOST = "drive.example.org";
export const HOME = "C:\\Users\\Alex";

export const THIS_DEVICE = "Arbeitslaptop";
export const OTHER_DEVICE = "Büro-PC";

export function folders(): Folder[] {
  return [
    {
      id: "f-main",
      name: "Hangar Drive",
      path: `${HOME}\\Hangar Drive`,
      status: { kind: "upToDate" },
      freezeDays: null,
      notSyncedCount: 0,
    },
    {
      id: "f-photos",
      name: "Fotos",
      path: "D:\\Fotos",
      status: { kind: "upToDate" },
      freezeDays: null,
      notSyncedCount: 0,
    },
  ];
}

export function activity(now: Millis): ActivityEntry[] {
  return [
    {
      kind: "file",
      id: "a1",
      folderId: "f-main",
      folderName: "Hangar Drive",
      name: "Bericht.docx",
      path: "Projekte/Bericht.docx",
      action: "changed",
      device: null,
      at: now - 2 * MINUTE,
    },
    {
      kind: "file",
      id: "a2",
      folderId: "f-photos",
      folderName: "Fotos",
      name: "Urlaub 014.jpg",
      path: "Urlaub/Urlaub 014.jpg",
      action: "fromDevice",
      device: OTHER_DEVICE,
      at: now - 62 * MINUTE,
    },
    {
      kind: "group",
      id: "a3",
      folderId: "f-photos",
      folderName: "Fotos",
      count: 120,
      at: now - 3 * HOUR,
    },
    {
      kind: "file",
      id: "a4",
      folderId: "f-main",
      folderName: "Hangar Drive",
      name: "Angebot Müller.pdf",
      path: "Kunden/Angebot Müller.pdf",
      action: "restored",
      device: null,
      at: now - 5 * HOUR,
    },
    {
      kind: "file",
      id: "a5",
      folderId: "f-main",
      folderName: "Hangar Drive",
      name: "Notizen.txt",
      path: "Notizen.txt",
      action: "deleted",
      device: null,
      at: now - DAY - 2 * HOUR,
    },
    {
      kind: "remoteDeleted",
      id: "a6",
      folderId: "f-photos",
      folderName: "Fotos",
      count: 14,
      device: OTHER_DEVICE,
      at: now - DAY - 4 * HOUR,
    },
    {
      kind: "file",
      id: "a7",
      folderId: "f-main",
      folderName: "Hangar Drive",
      name: "Plan 2027.xlsx",
      path: "Projekte/Plan 2027.xlsx",
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
      name: "Alter Laptop",
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
      folderName: "Hangar Drive",
      path: "Projekte",
      kind: "content",
      versions: [
        {
          id: "c1-a",
          name: "Bericht.docx",
          device: OTHER_DEVICE,
          modified: now - 40 * MINUTE,
          size: 48_200,
          original: true,
        },
        {
          id: "c1-b",
          name: `Bericht (Konflikt ${THIS_DEVICE} 2026-11-26).docx`,
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
      folderName: "Fotos",
      path: "Urlaub",
      kind: "caseOnly",
      versions: [
        {
          id: "c2-a",
          name: "Strand.JPG",
          device: OTHER_DEVICE,
          modified: now - 2 * DAY,
          size: 3_400_000,
          original: true,
        },
        {
          id: "c2-b",
          name: "strand.jpg",
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
      folderName: "Hangar Drive",
      dir: "Projekte",
      name: "Budget: Q1.xlsx",
      reason: { kind: "char", char: ":" },
      device: "MacBook",
    },
    {
      id: "n2",
      folderId: "f-main",
      folderName: "Hangar Drive",
      dir: "",
      name: "CON.txt",
      reason: { kind: "reserved", name: "CON" },
      device: "MacBook",
    },
    {
      id: "n3",
      folderId: "f-photos",
      folderName: "Fotos",
      dir: "Urlaub",
      name: "Notizen.",
      reason: { kind: "trailing" },
      device: "MacBook",
    },
    {
      id: "n4",
      folderId: "f-photos",
      folderName: "Fotos",
      dir: "",
      name: "Neu",
      reason: { kind: "cannotCreate" },
      device: OTHER_DEVICE,
    },
  ];
}

export function notSynced(): NotSyncedEntry[] {
  return [
    { path: "Projekte\\Verknüpfung zu Server.lnk", reason: "link" },
    { path: "Projekte\\Archiv", reason: "link" },
    { path: "desktop.ini", reason: "system" },
  ];
}

export function timeline(now: Millis, folderId: string): TimelineEntry[] {
  const other = folderId === "f-photos" ? "Alter Laptop" : OTHER_DEVICE;
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
      reanchored: true,
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
    {
      id: "t5",
      at: now - DAY - 9 * HOUR,
      device: THIS_DEVICE,
      changed: 4,
      added: 2,
      deleted: 0,
      reanchored: false,
    },
    {
      id: "t6",
      at: now - 3 * DAY,
      device: other,
      changed: 2,
      added: 0,
      deleted: 3,
      reanchored: false,
    },
    {
      id: "t7",
      at: now - 6 * DAY,
      device: THIS_DEVICE,
      changed: 0,
      added: 40,
      deleted: 0,
      reanchored: false,
    },
  ];
}

/** The tree of one version; older versions differ more from now. */
export function tree(entryId: string): TreeNode[] {
  const age = Number(entryId.slice(1)) || 1;
  const nodes: TreeNode[] = [
    { path: "Projekte", name: "Projekte", depth: 0, kind: "dir", diff: "same" },
    {
      path: "Projekte/Bericht.docx",
      name: "Bericht.docx",
      depth: 1,
      kind: "file",
      diff: "different",
    },
    { path: "Projekte/Plan.xlsx", name: "Plan.xlsx", depth: 1, kind: "file", diff: "same" },
    {
      path: "Projekte/Skizze.png",
      name: "Skizze.png",
      depth: 1,
      kind: "file",
      diff: age > 2 ? "different" : "same",
    },
    { path: "Kunden", name: "Kunden", depth: 0, kind: "dir", diff: "same" },
    {
      path: "Kunden/Angebot Müller.pdf",
      name: "Angebot Müller.pdf",
      depth: 1,
      kind: "file",
      diff: age > 3 ? "missing" : "same",
    },
    { path: "Kunden/Vertrag.pdf", name: "Vertrag.pdf", depth: 1, kind: "file", diff: "same" },
    { path: "Notizen.txt", name: "Notizen.txt", depth: 0, kind: "file", diff: "missing" },
    {
      path: "Einkauf.md",
      name: "Einkauf.md",
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
      name: "Notizen.txt",
      dir: "",
      deletedAt: now - DAY - 2 * HOUR,
      device: THIS_DEVICE,
    },
    { id: "x2", name: "Alt.pdf", dir: "Projekte", deletedAt: now - 6 * DAY, device: OTHER_DEVICE },
    {
      id: "x3",
      name: "Entwurf 3.docx",
      dir: "Projekte/Entwürfe",
      deletedAt: now - 9 * DAY,
      device: OTHER_DEVICE,
    },
    {
      id: "x4",
      name: "Rechnung 2025-11.pdf",
      dir: "Kunden",
      deletedAt: now - 15 * DAY,
      device: THIS_DEVICE,
    },
  ];
}

export function massDeleteList(count: number): string[] {
  return Array.from(
    { length: count },
    (_, i) => `Urlaub/Urlaub ${String(i + 1).padStart(3, "0")}.jpg`,
  );
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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
