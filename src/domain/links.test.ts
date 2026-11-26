import { describe, expect, it } from "vitest";

import { cleanLink, groupHex, linkKind } from "./links";

describe("linkKind", () => {
  it.each([
    ["https://drive.example.org/join#k7Qm2xR9", "invite"],
    ["https://drive.example.org/join#k7Qm2xR9.3f9a12c0.pinQ", "invite"],
    ["https://example.org/drive/join#token", "invite"],
    ["  https://drive.example.org/join#tok  ", "invite"],
    ["http://localhost:8080/join#tok", "invite"],
    ["hangar-drive://join#tok.3f9a@https://drive.example.org/", "invite"],
    ["HANGAR-DRIVE://pair#Z4mK8q", "pair"],
    ["hangar-drive://pair#Z4mK8q", "pair"],
    ["hangar-drive://recover#AQID", "recover"],
    ["hangar-drive://recover#AQ\nID", "recover"],
  ])("reads %s as %s", (text, kind) => {
    expect(linkKind(text)).toBe(kind);
  });

  it.each([
    "",
    "kein Link",
    "https://drive.example.org/join",
    "https://drive.example.org/join#",
    "https://drive.example.org/other#x",
    "hangar-drive://pair",
    "hangar-drive://pair#",
    "hangar-drive://update#x",
    "ftp://drive.example.org/join#x",
  ])("refuses %s", (text) => {
    expect(linkKind(text)).toBeNull();
  });
});

describe("cleanLink", () => {
  it("removes white space a printed or mailed link picks up", () => {
    expect(cleanLink(" hangar-drive://recover#AQID\n  BAUG \t")).toBe(
      "hangar-drive://recover#AQIDBAUG",
    );
  });
});

describe("groupHex", () => {
  it("groups an ID by four for comparing", () => {
    expect(groupHex("3F9A12C08B7E44D1A0B2C3D4E5F60718")).toBe(
      "3f9a 12c0 8b7e 44d1 a0b2 c3d4 e5f6 0718",
    );
  });
});
