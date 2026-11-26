// Developer tool, only next to the mock backend and never in a Tauri build: switches the mock's
// scenario and the outcome of the next action, so every state of the UX concept can be opened in
// the dev server. Its labels are English on purpose: it is not part of the product and has no
// entries in the dictionaries.

import { useState } from "react";

import { MockBackend, MOCK_INPUTS, type MockControls } from "../backend/mock/mockBackend";
import { SCENARIOS, isScenarioId } from "../backend/mock/scenarios";
import { useBackend } from "../ui/backendContext";

type Options<K extends keyof MockControls> = readonly MockControls[K][];

const PICKS: Options<"pick"> = [
  "ok",
  "existing",
  "network",
  "root",
  "system",
  "nested",
  "noAccess",
  "wrongFolder",
  "cancel",
];
const RESTORES: Options<"restore"> = [
  "done",
  "renamed",
  "waitBudget",
  "noSpace",
  "expired",
  "failed",
];
const SAVES: Options<"save"> = ["saved", "inSync", "cancel"];
const ANSWERS: Options<"pairAnswer"> = ["link", "typed", "none"];
const NUMBERS: Options<"folderNumber"> = ["number", "offline"];
const OLDER: Options<"olderCheck"> = ["stillOlder", "resolved"];
const FAILS = ["none", "notImplemented", "busy", "unexpected"] as const;
const CLIPBOARDS = {
  invite: MOCK_INPUTS.invite,
  "invite (used)": "https://drive.example.org/join#used",
  pair: MOCK_INPUTS.pair,
  "recovery code": "D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY",
  empty: "",
} as const;

export default function MockPanel() {
  const backend = useBackend();
  const [open, setOpen] = useState(false);
  const [, setRound] = useState(0);
  if (!(backend instanceof MockBackend)) return null;
  const mock = backend;
  const refresh = () => {
    setRound((value) => value + 1);
  };

  const select = <K extends keyof MockControls>(key: K, options: Options<K>, label: string) => (
    <label className="mock-field">
      <span>{label}</span>
      <select
        value={String(mock.controls[key])}
        onChange={(event) => {
          const found = options.find((option) => String(option) === event.target.value);
          if (found !== undefined) mock.controls[key] = found;
          refresh();
        }}
      >
        {options.map((option) => (
          <option key={String(option)} value={String(option)}>
            {String(option)}
          </option>
        ))}
      </select>
    </label>
  );

  if (!open) {
    return (
      <button
        type="button"
        className="mock-toggle"
        onClick={() => {
          setOpen(true);
        }}
      >
        Mock
      </button>
    );
  }

  return (
    <aside className="mock-panel" aria-label="Mock backend">
      <div className="mock-head">
        <strong>Mock backend</strong>
        <button
          type="button"
          className="mock-close"
          onClick={() => {
            setOpen(false);
          }}
        >
          Hide
        </button>
      </div>
      <label className="mock-field">
        <span>Scenario</span>
        <select
          value={mock.currentScenario}
          onChange={(event) => {
            const id = event.target.value;
            if (isScenarioId(id)) {
              mock.setScenario(id);
              const url = new URL(window.location.href);
              url.searchParams.set("scenario", id);
              window.history.replaceState(null, "", url);
            }
            refresh();
          }}
        >
          {SCENARIOS.map((scenario) => (
            <option key={scenario.id} value={scenario.id}>
              {scenario.label}
            </option>
          ))}
        </select>
      </label>
      {select("pick", PICKS, "Next folder pick")}
      {select("restore", RESTORES, "Next restore")}
      {select("save", SAVES, "Next save dialog")}
      {select("pairAnswer", ANSWERS, "New device answers via")}
      {select("folderNumber", NUMBERS, "Folder number")}
      {select("olderCheck", OLDER, "Check again")}
      <label className="mock-field">
        <span>Clipboard</span>
        <select
          value={
            Object.entries(CLIPBOARDS).find(([, text]) => text === mock.controls.clipboard)?.[0] ??
            "invite"
          }
          onChange={(event) => {
            const entry = Object.entries(CLIPBOARDS).find(([name]) => name === event.target.value);
            if (entry) mock.controls.clipboard = entry[1];
            refresh();
          }}
        >
          {Object.keys(CLIPBOARDS).map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
      </label>
      <label className="mock-field">
        <span>Next call fails</span>
        <select
          value={mock.controls.failNext ?? "none"}
          onChange={(event) => {
            const value = FAILS.find((option) => option === event.target.value);
            mock.controls.failNext = value === undefined || value === "none" ? null : value;
            refresh();
          }}
        >
          {FAILS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      <label className="mock-check">
        <input
          type="checkbox"
          onChange={(event) => {
            mock.setCamera(event.target.checked);
          }}
        />
        Camera present
      </label>
      <div className="mock-actions">
        <button
          type="button"
          onClick={() => {
            mock.clickTray("showProblem");
          }}
        >
          Tray: show problem
        </button>
        <button
          type="button"
          onClick={() => {
            mock.answerOffer("link");
          }}
        >
          New device answers now
        </button>
      </div>
      <p className="mock-note">
        Invite errors: {MOCK_INPUTS.inviteErrors}. Pairing: {MOCK_INPUTS.pairErrors}. Recovery:{" "}
        {MOCK_INPUTS.recovery}.
      </p>
    </aside>
  );
}
