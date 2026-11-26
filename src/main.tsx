import "./styles.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { createBackend } from "./backend";

// The window follows the system theme (UX 11: no theme setting). Set before the first render, so
// a light window does not briefly flash dark.
const darkScheme = window.matchMedia("(prefers-color-scheme: dark)");
function applySystemTheme(): void {
  document.documentElement.dataset.theme = darkScheme.matches ? "dark" : "light";
}
applySystemTheme();
darkScheme.addEventListener("change", applySystemTheme);

const root = document.getElementById("root");
if (!root) throw new Error("Element #root missing in index.html");

const backend = await createBackend(window.location.search);

createRoot(root).render(
  <StrictMode>
    <App backend={backend} />
  </StrictMode>,
);
