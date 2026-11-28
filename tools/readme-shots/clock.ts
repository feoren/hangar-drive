// A fixed clock for the README screenshots, so every time the app shows ("2 min ago") is the same
// in each run: it starts at FIXED_START and stands at SHOT_TIME once the driver freezes the scene.
// `new Date()` without arguments reads the same clock; every other form stays real.

interface ReadmeShotsControl {
  /** Set by the driver right before the screenshot: the clock stands still. */
  freeze: boolean;
}

declare global {
  interface Window {
    __readmeShots: ReadmeShotsControl;
  }
}

const control: ReadmeShotsControl = { freeze: false };
window.__readmeShots = control;

const FIXED_START = Date.UTC(2026, 10, 27, 14, 30, 0);
const SHOT_TIME = FIXED_START + 30_000;
const realNow = Date.now.bind(Date);
const clockOffset = FIXED_START - realNow();
Date.now = () => (control.freeze ? SHOT_TIME : Math.min(realNow() + clockOffset, SHOT_TIME));
window.Date = new Proxy(Date, {
  construct(target, args: unknown[], newTarget) {
    return Reflect.construct(target, args.length === 0 ? [Date.now()] : args, newTarget);
  },
});

export {};
