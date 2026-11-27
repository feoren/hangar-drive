import { describe, expect, it } from "vitest";

import type { Device } from "../backend/types";
import { createI18n } from "../i18n";
import { recoveryDeviceLabel, recoveryEndedText } from "./RecoverFlow";

const { t } = createI18n("de");

function device(id: string, name: string, added: number): Device {
  return { id, name, kind: "laptop", isThis: false, lastSeen: null, added };
}

describe("the old devices of a recovery", () => {
  const day = new Date(2026, 9, 27, 9, 15).getTime();
  const sameDay = new Date(2026, 9, 27, 18, 40).getTime();
  const other = new Date(2026, 9, 3, 12, 0).getTime();

  it("are named by the day they were added while their names are sealed", () => {
    const first = device("a", "", day);
    const all = [first, device("b", "", other)];
    expect(recoveryDeviceLabel(first, all, "de", t)).toBe("Gerät, hinzugefügt am 27. Oktober 2026");
  });

  it("carry the time when two were added on the same day", () => {
    const all = [device("a", "", day), device("b", "", sameDay)];
    const labels = all.map((each) => recoveryDeviceLabel(each, all, "de", t));
    expect(labels[0]).toMatch(/^Gerät, hinzugefügt am 27\. Oktober 2026.*09:15$/);
    expect(labels[1]).toMatch(/^Gerät, hinzugefügt am 27\. Oktober 2026.*18:40$/);
  });

  it("keep a name they have, and never show a blank one", () => {
    const named = device("a", "Alter Laptop", day);
    const blank = device("b", "  ", day);
    const all = [named, blank];
    expect(recoveryDeviceLabel(named, all, "de", t)).toBe("Alter Laptop");
    expect(recoveryDeviceLabel(blank, all, "de", t)).toBe("Gerät, hinzugefügt am 27. Oktober 2026");
  });
});

describe("a recovery that ended in its last step", () => {
  it("says so and names the reason", () => {
    const lead = "Die Wiederherstellung ist nicht abgeschlossen. Starte sie noch einmal.";
    expect(recoveryEndedText("used", t)).toBe(
      `${lead} Dieser Code wurde ersetzt. Nimm das neuere Blatt.`,
    );
    expect(recoveryEndedText("unknown", t)).toContain("gehört zu keinem Konto");
    expect(recoveryEndedText("insecure", t)).toContain("nicht verschlüsselt");
  });
});
