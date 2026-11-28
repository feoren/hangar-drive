// Renders the README screenshots into docs/images from the real frontend and the real mock
// backend (src/backend/mock/) in a headless Chromium based browser: one image per scene and color
// scheme, e.g. hangar-drive-dark.png (the overview) and hangar-drive-versions-light.png. Modeled on
// the readme-shots tools of Hangar and Hangar Note (MIT, same owner).
//
// Usage: pnpm readme:shots [--scene <name>]...   (default: every scene)
//
// The mock backend keeps its logic; only its example data (fixtures.ts), the starting state of
// each scene (scenarios.ts) and its dev setup (devMock.ts) are swapped for the English README
// versions in this folder, and the mock's dev panel is left out (noPanel.tsx). Starts its own Vite
// server on a free port, never touches a running Hangar Drive, and keeps all temporary files
// (browser profile, Vite cache) under tests/.tmp/readme-shots, which it removes at the end. A
// scene that gets stuck leaves the page as it stood in tests/.tmp/readme-shots-failed-<scene>.png.
import react from "@vitejs/plugin-react";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import path from "node:path";
import { createServer } from "vite";

import { findBrowser, launchBrowser, sleep, waitFor } from "./browser.mjs";
import { optimizePng, pngSize } from "./png.mjs";

const HERE = import.meta.dirname;
const REPO = path.resolve(HERE, "../..");
const WORK = path.join(REPO, "tests/.tmp/readme-shots");
const OUT_DIR = path.join(REPO, "docs/images");

/** The window in CSS pixels, drawn at twice the density so the text stays sharp on any screen. */
const WIDTH = 800;
const HEIGHT = 560;
const SCALE = 2;
const KB = 1024;
const SCHEMES = ["dark", "light"];
const TITLE = "README-SHOTS-HARNESS";

/**
 * Modules of src/ that the README build serves from this folder instead: the mock's example data,
 * its scenarios, its dev setup and its dev panel. Keys are paths below src/ without extension.
 */
const SWAPS = {
  "backend/mock/fixtures": "fixtures.ts",
  "backend/mock/scenarios": "scenarios.ts",
  "backend/mock/devMock": "devMock.ts",
  "dev/MockPanel": "noPanel.tsx",
};

/** Clicks the first element matching `selector` whose text contains `text` (if given). */
const click = (selector, text = null) => `(() => {
  const all = [...document.querySelectorAll(${JSON.stringify(selector)})];
  const target = all.find((el) => ${JSON.stringify(text)} === null || el.textContent.includes(${JSON.stringify(text)}));
  if (!target) throw new Error("Nothing to click: " + ${JSON.stringify(`${selector} ${text ?? ""}`)});
  target.click();
  return true;
})()`;

/** True once an element matching `selector` exists whose text contains `text` (if given). */
const shows = (selector, text = null) => `(() => {
  const all = [...document.querySelectorAll(${JSON.stringify(selector)})];
  return all.some((el) => ${JSON.stringify(text)} === null || el.textContent.includes(${JSON.stringify(text)}));
})()`;

/** Types `value` into the field matching `selector` the way React notices it. */
const type = (selector, value) => `(() => {
  const field = document.querySelector(${JSON.stringify(selector)});
  if (!field) throw new Error("No field " + ${JSON.stringify(selector)});
  const proto = field instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value").set.call(field, ${JSON.stringify(value)});
  field.dispatchEvent(new Event("input", { bubbles: true }));
  return true;
})()`;

/** Takes the focus away from where a click left it, so no focus ring shows. */
const BLUR = `(() => {
  const active = document.activeElement;
  if (active instanceof HTMLElement) active.blur();
  return true;
})()`;

/** The main window is up: the header and at least one folder. */
const MAIN_BOOT = `(document.querySelector(".row-name") !== null)`;

/** The setup is up: its first choice. */
const SETUP_BOOT = shows("button", "Start with an invite link");

/** Presses a key combination in the window, as the shortcuts module reads it. */
const key = (keyName, { ctrl = false, shift = false } = {}) => `(() => {
  window.dispatchEvent(new KeyboardEvent("keydown", {
    key: ${JSON.stringify(keyName)}, ctrlKey: ${ctrl}, shiftKey: ${shift}, bubbles: true, cancelable: true,
  }));
  return true;
})()`;

/** Opens the row menu of the folder `name` and chooses `item` in it. */
const folderMenu = (name, item) => [
  {
    run: click(`button[aria-label="Actions for “${name}”"]`),
    ready: shows("[role=menuitem]", item),
  },
  { run: click("[role=menuitem]", item), ready: shows("[role=dialog]") },
];

/**
 * The scenes, in README order. `file`: the image name without scheme; `maxBytes`: the size limit
 * of one image; `height`: the window height in CSS pixels (default HEIGHT); `boot`: what must show
 * for the app to count as started; `steps`: what to run once the app is up, each followed by what
 * must show before the next. scenarios.ts reads the scene's name and sets the state it starts with.
 */
const SCENES = [
  {
    // The hero: four folders with their size and number of files, Photos uploading and Projects
    // downloading, the status and the network traffic of the last minute in the header.
    name: "overview",
    file: "hangar-drive",
    maxBytes: 300 * KB,
    // As tall as the four folders need, without an empty lower half.
    height: 400,
    steps: [
      { ready: `(${shows(".traffic")} && ${shows("body", "Syncing 120 files")})`, timeout: 10_000 },
    ],
  },
  {
    // The first start with an invite link pasted: the app checked it and found the server.
    name: "invite",
    file: "hangar-drive-invite",
    maxBytes: 300 * KB,
    boot: SETUP_BOOT,
    steps: [
      { run: click("button", "Start with an invite link"), ready: shows("input, textarea") },
      {
        run: type("input, textarea", "https://drive.example.org/join#k7Qm2xR9"),
        ready: shows("body", "Connected to drive.example.org"),
      },
      { run: BLUR, ready: "true" },
    ],
  },
  {
    // Adding a device: the pairing link and its QR code on the device already set up.
    name: "add-device",
    file: "hangar-drive-add-device",
    maxBytes: 300 * KB,
    steps: [
      {
        run: key("D", { ctrl: true, shift: true }),
        ready: shows("[role=dialog] button", "Add device"),
      },
      {
        run: click("[role=dialog] button", "Add device"),
        ready: shows("[role=dialog] img, [role=dialog] svg"),
      },
      { run: BLUR, ready: "true" },
    ],
  },
  {
    // The account's devices: this one, another one and one not seen for months, with the
    // recovery code below them.
    name: "devices",
    file: "hangar-drive-devices",
    maxBytes: 300 * KB,
    steps: [
      {
        run: key("D", { ctrl: true, shift: true }),
        ready: shows("[role=dialog]", "Recovery code"),
      },
      { run: BLUR, ready: "true" },
    ],
  },
  {
    // Earlier versions of a folder: the timeline, newest first, and what differs from now.
    name: "versions",
    file: "hangar-drive-versions",
    maxBytes: 300 * KB,
    steps: [...folderMenu("Documents", "Earlier versions"), { run: BLUR, ready: "true" }],
  },
  {
    // Two devices changed the same file: both versions stay, named after their device.
    name: "conflicts",
    file: "hangar-drive-conflicts",
    maxBytes: 300 * KB,
    // Tall enough that the centered question leaves the banner above it whole.
    height: 620,
    steps: [
      { run: click("button", "View"), ready: shows("[role=dialog]", "Keep both") },
      { run: BLUR, ready: "true" },
    ],
  },
  {
    // Many files disappeared at once: the deletions wait and the app asks first.
    name: "mass-delete",
    file: "hangar-drive-mass-delete",
    maxBytes: 300 * KB,
    // As tall as the conflicts shot next to it in the README table.
    height: 620,
    steps: [
      { ready: shows("[role=alertdialog], [role=dialog]", "342 files deleted") },
      { run: BLUR, ready: "true" },
    ],
  },
];

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/** Serves the modules in SWAPS from this folder whenever src/ imports them. */
function swapMockModules() {
  const src = path.join(REPO, "src");
  const swaps = new Map(
    Object.entries(SWAPS).map(([from, to]) => [path.join(src, from), path.join(HERE, to)]),
  );
  return {
    name: "readme-shots-swap",
    enforce: "pre",
    resolveId(source, importer) {
      // Only imports from src/: the swapped modules here import the real ones they wrap.
      if (!importer || !source.startsWith(".") || !path.resolve(importer).startsWith(src)) {
        return null;
      }
      const target = path.resolve(path.dirname(importer), source).replace(/\.tsx?$/, "");
      return swaps.get(target) ?? null;
    },
  };
}

async function startVite(version) {
  const port = await freePort();
  const server = await createServer({
    configFile: false,
    root: HERE,
    plugins: [swapMockModules(), react()],
    define: {
      __HANGAR_DRIVE_BUILD__: "null",
      __HANGAR_DRIVE_VERSION__: JSON.stringify(version),
      __HANGAR_DRIVE_BACKEND__: JSON.stringify("mock"),
    },
    cacheDir: path.join(WORK, "vite-cache"),
    clearScreen: false,
    logLevel: "warn",
    server: {
      host: "127.0.0.1",
      port,
      strictPort: true,
      hmr: false,
      watch: null,
      fs: { allow: [REPO] },
    },
  });
  await server.listen();
  return { server, url: `http://127.0.0.1:${port}/` };
}

/**
 * Stops every CSS animation on a fixed frame: finite ones (a dialog opening) at their end,
 * endless ones (a spinner) halfway through their cycle.
 */
const FREEZE_ANIMATIONS = `(() => {
  for (const animation of document.getAnimations()) {
    const timing = animation.effect?.getComputedTiming();
    const duration = typeof timing?.duration === "number" ? timing.duration : 0;
    if (timing?.iterations !== Infinity) {
      animation.finish();
      continue;
    }
    animation.pause();
    animation.currentTime = duration * 0.5;
  }
  return true;
})()`;

/** Loads one scene in one color scheme and returns the raw screenshot. */
async function render(page, url, scene, scheme) {
  await page.send("Emulation.setDeviceMetricsOverride", {
    width: WIDTH,
    height: scene.height ?? HEIGHT,
    deviceScaleFactor: SCALE,
    mobile: false,
  });
  await page.send("Emulation.setFocusEmulationEnabled", { enabled: true });
  await page.send("Emulation.setTimezoneOverride", { timezoneId: "UTC" }).catch(() => undefined);
  await page.send("Emulation.setLocaleOverride", { locale: "en-US" }).catch(() => undefined);
  await page.send("Emulation.setEmulatedMedia", {
    features: [
      { name: "prefers-color-scheme", value: scheme },
      { name: "prefers-reduced-motion", value: "no-preference" },
    ],
  });

  // First load only to reach the origin's storage, then start the app with the scene's choice.
  await page.goto(url);
  if ((await page.evaluate("document.title")) !== TITLE) {
    throw new Error(`${url} does not serve the screenshot harness.`);
  }
  await page.evaluate(`(() => {
    localStorage.clear();
    localStorage.setItem("readmeShots.scene", ${JSON.stringify(JSON.stringify(scene.name))});
    return true;
  })()`);
  await page.goto(url);

  await waitFor(() => page.evaluate(scene.boot ?? MAIN_BOOT), { what: "the started app" });
  await page.evaluate(`document.fonts.ready.then(() => true)`);
  for (const [index, step] of scene.steps.entries()) {
    if (step.run) await page.evaluate(step.run);
    await waitFor(() => page.evaluate(step.ready), {
      timeout: step.timeout ?? 20_000,
      what: `step ${index + 1} of the scene ${scene.name}`,
    });
  }
  // Let the window settle, move the pointer away, stop the clock and freeze every animation.
  await sleep(600);
  await page.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: WIDTH - 2, y: 2 });
  await page.evaluate(`(() => { window.__readmeShots.freeze = true; return true; })()`);
  await sleep(400);
  await page.evaluate(FREEZE_ANIMATIONS);
  await sleep(200);
  return page.screenshot();
}

/** Scene names from `--scene a --scene b` or `--scene a,b`; every scene without the option. */
function chosenScenes(argv) {
  const names = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--scene") names.push(...(argv[(i += 1)] ?? "").split(","));
    else if (arg.startsWith("--scene=")) names.push(...arg.slice(8).split(","));
    else throw new Error(`Unknown argument ${arg}. Usage: run.mjs [--scene <name>]...`);
  }
  if (names.length === 0) return SCENES;
  const known = SCENES.map((scene) => scene.name);
  const unknown = names.filter((name) => !known.includes(name));
  if (unknown.length > 0) {
    throw new Error(`Unknown scene ${unknown.join(", ")}. Known: ${known.join(", ")}.`);
  }
  return SCENES.filter((scene) => names.includes(scene.name));
}

function removeWork() {
  try {
    rmSync(WORK, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  } catch (error) {
    console.warn(`Could not remove ${WORK}: ${error instanceof Error ? error.message : error}`);
  }
}

async function main() {
  const scenes = chosenScenes(process.argv.slice(2));
  const { version } = JSON.parse(readFileSync(path.join(REPO, "package.json"), "utf8"));
  const browserPath = findBrowser();
  rmSync(WORK, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  mkdirSync(WORK, { recursive: true });
  mkdirSync(OUT_DIR, { recursive: true });

  let vite = null;
  let page = null;
  try {
    vite = await startVite(version);
    console.log(`Vite ${vite.url}, browser ${browserPath}, version ${version}`);
    page = await launchBrowser(browserPath, path.join(WORK, "profile"));
    for (const scene of scenes) {
      for (const scheme of SCHEMES) {
        const raw = await render(page, vite.url, scene, scheme).catch(async (error) => {
          // What the page showed when the scene got stuck, kept next to the work folder.
          const failed = path.join(REPO, `tests/.tmp/readme-shots-failed-${scene.name}.png`);
          await page
            .screenshot()
            .then((shot) => writeFileSync(failed, shot))
            .then(() => console.error(`The page as it stood: ${path.relative(REPO, failed)}`))
            .catch(() => undefined);
          throw error;
        });
        const optimized = optimizePng(raw);
        const { width, height } = pngSize(optimized);
        const name = `${scene.file}-${scheme}.png`;
        const expected = { width: WIDTH * SCALE, height: (scene.height ?? HEIGHT) * SCALE };
        if (width !== expected.width || height !== expected.height) {
          throw new Error(
            `${name}: got ${width} x ${height}, expected ${expected.width} x ${expected.height}.`,
          );
        }
        if (optimized.length > scene.maxBytes) {
          throw new Error(
            `${name}: ${optimized.length} bytes, more than the ${scene.maxBytes} allowed.`,
          );
        }
        const target = path.join(OUT_DIR, name);
        writeFileSync(target, optimized);
        console.log(
          `${path.relative(REPO, target)}: ${width} x ${height}, ${Math.round(optimized.length / KB)} KB` +
            ` (raw ${Math.round(raw.length / KB)} KB)`,
        );
      }
    }
    const problems = page.logs.filter((line) => /^(error|exception)/i.test(line));
    if (problems.length > 0) console.warn(`Page reported:\n  ${problems.join("\n  ")}`);
  } finally {
    await page?.close().catch(() => undefined);
    await vite?.server.close().catch(() => undefined);
    removeWork();
  }
}

main().catch((error) => {
  console.error(`readme-shots: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
