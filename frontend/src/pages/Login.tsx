import { useState, type FormEvent } from "react";
import { useApp } from "../app/context";

export function Login() {
  const { t, lang, setLang } = useApp();
  const { login } = useApp();
  const [u, setU] = useState("analyst");
  const [p, setP] = useState("");
  const [err, setErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    try { await login(u, p); } catch { setErr(true); } finally { setBusy(false); }
  };
  return (
    <main className="login" id="main">
      <form className="login-card" onSubmit={submit}>
        <p className="brand-name big">ACRS</p>
        <p className="muted">{t("app.tagline")}</p>
        <h1>{t("auth.title")}</h1>
        <label>{t("auth.username")}<input value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" required /></label>
        <label>{t("auth.password")}<input type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" required /></label>
        {err && <p className="tone-text-crit" role="alert">{t("auth.failed")}</p>}
        <button className="btn primary" disabled={busy}>{t("auth.submit")}</button>
        <p className="muted small">{t("auth.hint")}</p>
        <button type="button" className="btn ghost" onClick={() => setLang(lang === "ar" ? "en" : "ar")}>{t("ui.lang.switch")}</button>
        <p className="simnote small">{t("app.simulation")}</p>
        <p className="muted small">{t("app.copyright")}</p>
      </form>
    </main>
  );
}
