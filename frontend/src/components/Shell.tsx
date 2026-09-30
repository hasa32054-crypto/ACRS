import { useState, type ReactNode } from "react";
import { useApp } from "../app/context";
import type { Key } from "../lib/i18n";

export const NAV: { page: string; key: Key }[] = [
  { page: "", key: "nav.command" }, { page: "incidents", key: "nav.incidents" },
  { page: "emergency", key: "nav.emergency" }, { page: "assets", key: "nav.assets" },
  { page: "lab", key: "nav.lab" }, { page: "memory", key: "nav.memory" },
  { page: "reports", key: "nav.reports" }, { page: "audit", key: "nav.audit" },
];

export function Shell({ page, online, emergency, children }:
  { page: string; online: boolean; emergency: number; children: ReactNode }) {
  const { t, lang, setLang, theme, toggleTheme, user, logout, toasts } = useApp();
  const [open, setOpen] = useState(false);
  return (
    <div className="shell">
      <a className="skip" href="#main">{lang === "ar" ? "انتقل إلى المحتوى" : "Skip to content"}</a>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">{t("app.name")}</span>
          <span className="brand-tag">{t("app.tagline")}</span>
        </div>
        <div className="top-tools">
          <span className={`live ${online ? "on" : ""}`}>{online ? t("ui.live") : t("ui.offline")}</span>
          <button className="btn ghost" onClick={() => setLang(lang === "ar" ? "en" : "ar")} lang={lang === "ar" ? "en" : "ar"}>
            {t("ui.lang.switch")}
          </button>
          <button className="btn ghost" onClick={toggleTheme} aria-pressed={theme === "light"}>
            {theme === "dark" ? t("ui.theme.light") : t("ui.theme.dark")}
          </button>
          {user && <span className="who">{user.username} <span className="muted">({user.role})</span></span>}
          {user && <button className="btn ghost" onClick={logout}>{t("auth.logout")}</button>}
          <button className="btn ghost menu-btn" aria-expanded={open} aria-controls="nav" onClick={() => setOpen(!open)}>
            {t("ui.menu")}
          </button>
        </div>
      </header>
      <nav id="nav" className={`rail ${open ? "open" : ""}`} aria-label="ACRS">
        <ul>
          {NAV.map((n) => (
            <li key={n.page}>
              <a href={`#/${n.page}`} aria-current={page === n.page ? "page" : undefined} onClick={() => setOpen(false)}>
                {t(n.key)}
                {n.page === "emergency" && emergency > 0 && <span className="count">{emergency}</span>}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <main id="main" tabIndex={-1}>{children}</main>
      <footer className="simbar" role="note"><span>{t("app.simulation")}</span><span className="copyright">{t("app.copyright")}</span></footer>
      <div className="toasts" aria-live="polite">
        {toasts.map((x) => <p key={x.id} className={`toast tone-${x.tone}`}>{x.text}</p>)}
      </div>
    </div>
  );
}
