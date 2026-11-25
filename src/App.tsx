import { useT } from "./i18n";

/** The main window. Until the first sync feature lands it only shows the empty state. */
export function App() {
  const t = useT();
  const name = t("app.name");
  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-title">{name}</h1>
      </header>
      <main className="empty-state" aria-labelledby="empty-title">
        <h2 id="empty-title" className="empty-title">
          {t("empty.title")}
        </h2>
        <p className="empty-body">{t("empty.body", { app: name })}</p>
      </main>
    </div>
  );
}
