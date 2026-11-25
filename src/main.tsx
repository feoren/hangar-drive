import "./styles.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { createTranslator, detectLanguage, I18nContext, setCurrentLanguage } from "./i18n";

// The window follows the system theme until there are settings. Set before the first render, so
// a light window does not briefly flash dark.
const darkScheme = window.matchMedia("(prefers-color-scheme: dark)");
function applySystemTheme(): void {
  document.documentElement.dataset.theme = darkScheme.matches ? "dark" : "light";
}
applySystemTheme();
darkScheme.addEventListener("change", applySystemTheme);

const language = detectLanguage(navigator.language);
setCurrentLanguage(language);
document.documentElement.lang = language;

const root = document.getElementById("root");
if (!root) throw new Error("Element #root missing in index.html");

createRoot(root).render(
  <StrictMode>
    <I18nContext.Provider value={createTranslator(language)}>
      <App />
    </I18nContext.Provider>
  </StrictMode>,
);
