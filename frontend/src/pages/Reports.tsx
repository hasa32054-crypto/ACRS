import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import { api } from "../lib/api";
import { Bars, Empty, ErrorBox, Loading, Panel } from "../components/ui";
import { can, fmtDateTime, fmtMs, pct } from "../lib/format";
import type { Kpis, Report, StoredReport } from "../lib/types";

function KpiList({ k }: { k: Kpis }) {
  const { t, lang } = useApp();
  return (
    <dl className="kpis compact">
      <div><dt>{t("rep.incidents")}</dt><dd className="num">{k.incidents}</dd></div>
      <div><dt>{t("kpi.auto")}</dt><dd className="num">{pct(k.auto_rate_pct)}</dd></div>
      <div><dt>{t("rep.mttd")}</dt><dd className="num">{fmtMs(k.mttd_ms_avg, lang)}</dd></div>
      <div><dt>{t("kpi.mttc")}</dt><dd className="num">{fmtMs(k.mttc_ms_avg, lang)}</dd></div>
      <div><dt>{t("rep.p95")}</dt><dd className="num">{fmtMs(k.mttc_ms_p95, lang)}</dd></div>
      <div><dt>{t("rep.withinTarget")}</dt><dd className="num">{pct(k.mttc_within_target_pct)}</dd></div>
      <div><dt>{t("rep.fp")}</dt><dd className="num">{k.false_positives}</dd></div>
      <div><dt>{t("rep.escalations")}</dt><dd className="num">{k.escalations}</dd></div>
      <div><dt>{t("kpi.continuity")}</dt><dd className="num">{pct(k.business_continuity_pct)}</dd></div>
    </dl>
  );
}

export function Reports() {
  const { t, e, x, lang, user, toast } = useApp();
  const tick = useLiveTick((m) => m.type === "report" || m.type === "state", 1500);
  const live = useFetch<Report>("/reports/kpis?hours=24", [tick]);
  const hourly = useFetch<StoredReport[]>("/reports/hourly", [tick]);
  const generate = async () => {
    try { await api("/reports/hourly/generate", { method: "POST" }); toast(t("rep.generated"), "ok"); await hourly.reload(); }
    catch (err) { toast(x((err as Error).message), "crit"); }
  };
  return (
    <div className="page">
      <header className="page-head"><h1>{t("nav.reports")}</h1>
        {can(user?.role, "analyst") && <button className="btn primary" onClick={generate}>{t("rep.generate")}</button>}</header>
      {live.error ? <ErrorBox error={live.error} retry={live.reload} /> : !live.data ? <Loading /> : (
        <Panel title={t("rep.live")}>
          <KpiList k={live.data.kpis} />
          <div className="grid-3">
            <div><h3>{t("rep.byState")}</h3><Bars data={live.data.by_state} label={e} /></div>
            <div><h3>{t("rep.byAttack")}</h3><Bars data={live.data.by_attack_type} label={x} /></div>
            <div><h3>{t("rep.byLevel")}</h3><Bars data={live.data.by_level} label={e} /></div>
          </div>
          <h3>{t("rep.recs")}</h3>
          <ul className="reasons">{live.data.recommendations.map((r, i) => <li key={i}>{lang === "ar" ? r.ar : r.en}</li>)}</ul>
        </Panel>
      )}
      <Panel title={t("rep.hourly")}>
        {hourly.error ? <ErrorBox error={hourly.error} retry={hourly.reload} /> : !hourly.data ? <Loading /> :
          hourly.data.length === 0 ? <Empty>{t("rep.empty")}</Empty> : (
            <ol className="reports">
              {hourly.data.map((r) => (
                <li key={r.id}>
                  <h3 className="num">{fmtDateTime(r.window_start, lang)} → {fmtDateTime(r.window_end, lang)}</h3>
                  <KpiList k={r.kpis} />
                  <ul className="reasons small">{r.body.recommendations.map((x, i) => <li key={i}>{lang === "ar" ? x.ar : x.en}</li>)}</ul>
                </li>
              ))}
            </ol>
          )}
      </Panel>
    </div>
  );
}
