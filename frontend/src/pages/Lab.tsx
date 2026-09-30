import { useState } from "react";
import { useApp } from "../app/context";
import { useFetch } from "../app/hooks";
import { go } from "../app/router";
import { api, ApiError } from "../lib/api";
import { Badge, ErrorBox, Loading } from "../components/ui";
import { BreakerBanner } from "../components/BreakerBanner";
import { can } from "../lib/format";
import type { Key } from "../lib/i18n";
import type { Scenario } from "../lib/types";

export function Lab() {
  const { t, x, lang, user, toast } = useApp();
  const q = useFetch<Scenario[]>("/sim/scenarios");
  const [busy, setBusy] = useState<string | null>(null);
  const run = async (s: Scenario, mode: "success" | "failure") => {
    setBusy(s.id + mode);
    try {
      const r = await api<{ incident_ids: string[] }>(`/sim/scenarios/${s.id}/run`, { method: "POST", json: { mode } });
      toast(`${t("lab.started")}: ${lang === "ar" ? s.title_ar : s.title_en}`, "ok");
      if (r.incident_ids.length) go(r.incident_ids.length === 1 ? `incidents/${r.incident_ids[0]}` : "incidents");
      else toast(t("lab.noIncident"), "info");
    } catch (err) {
      toast(err instanceof ApiError && err.status === 403 ? t("ui.forbidden") : x((err as Error).message), "crit");
    } finally { setBusy(null); }
  };
  if (q.error) return <div className="page"><ErrorBox error={q.error} retry={q.reload} /></div>;
  if (!q.data) return <div className="page"><Loading /></div>;
  const cats = [...new Set(q.data.map((s) => s.category))];
  const allowed = can(user?.role, "analyst");
  return (
    <div className="page">
      <header className="page-head"><h1>{t("nav.lab")}</h1><span className="muted">{t("lab.title")}</span></header>
      <p className="lead">{t("lab.hint")}</p>
      <BreakerBanner />
      {cats.map((c) => (
        <section key={c} className="lab-cat">
          <h2>{t(`cat.${c}` as Key)}</h2>
          <ul className="lab-list">
            {q.data!.filter((s) => s.category === c).map((s) => (
              <li key={s.id} className="lab-item">
                <div className="lab-text">
                  <p className="lab-title">{lang === "ar" ? s.title_ar : s.title_en}
                    {s.edge_case && <Badge tone="mem">{t("lab.edge")} {s.edge_case}</Badge>}</p>
                  <p className="muted small">{t("lab.target")}: {s.target} · {t(`fail.${s.default_failure}` as Key)}</p>
                </div>
                <div className="btnrow">
                  <button className="btn" disabled={!allowed || !!busy} onClick={() => run(s, "success")}>{t("lab.success")}</button>
                  <button className="btn warn" disabled={!allowed || !!busy} onClick={() => run(s, "failure")}>{t("lab.failure")}</button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
