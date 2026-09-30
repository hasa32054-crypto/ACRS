import { useState } from "react";
import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import { api } from "../lib/api";
import { Badge, ErrorBox, Loading, Panel, Sparkline } from "../components/ui";
import { assetTone, can, riskTone, stateTone } from "../lib/format";
import type { Key } from "../lib/i18n";
import type { Asset, IncidentSummary } from "../lib/types";

export function Assets() {
  const { t, e, x, user, toast } = useApp();
  const tick = useLiveTick((m) => m.type === "state" || m.type === "reentry");
  const q = useFetch<Asset[]>("/assets", [tick]);
  const [sel, setSel] = useState<number | null>(null);
  const d = useFetch<{ asset: Asset; risk_history: { score: number }[]; incidents: IncidentSummary[] }>(
    sel ? `/assets/${sel}` : null, [tick]);

  const toggleCw = async (a: Asset) => {
    try {
      await api(`/assets/${a.id}/change-window`, { method: "PATCH", json: { in_change_window: !a.in_change_window } });
      toast(t("ast.toggleCw"), "ok");
      await Promise.all([q.reload(), d.reload()]);
    } catch (err) { toast(x((err as Error).message), "crit"); }
  };

  if (q.error) return <div className="page"><ErrorBox error={q.error} retry={q.reload} /></div>;
  if (!q.data) return <div className="page"><Loading /></div>;
  return (
    <div className="page">
      <header className="page-head"><h1>{t("nav.assets")}</h1></header>
      <div className="assets-layout">
        <div>
          {[0, 1, 2].map((tier) => (
            <section key={tier} className="tier-block">
              <h2>{t(`ast.tier${tier}` as Key)}</h2>
              <ul className="asset-list">
                {q.data!.filter((a) => a.tier === tier).map((a) => (
                  <li key={a.id}>
                    <button className={`asset ${sel === a.id ? "sel" : ""}`} onClick={() => setSel(a.id)} aria-pressed={sel === a.id}>
                      <span className={`dot tone-${assetTone(a.status)}`} aria-hidden="true" />
                      <span className="asset-name">{a.hostname}</span>
                      <span className="muted small">{x(a.role)}</span>
                      <span className={`num small tone-text-${riskTone(a.current_risk)}`}>{a.current_risk}</span>
                      <span className="small">{t(`ast.${a.status}` as Key)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
        <Panel title={d.data?.asset.hostname ?? t("nav.assets")} className="sticky">
          {!sel ? <p className="muted">{t("ast.select")}</p> : !d.data ? <Loading /> : (
            <>
              <dl className="kv">
                <dt>IP</dt><dd className="num">{d.data.asset.ip}</dd>
                <dt>{t("ast.status")}</dt><dd><Badge tone={assetTone(d.data.asset.status)}>{t(`ast.${d.data.asset.status}` as Key)}</Badge></dd>
                <dt>{t("ast.role")}</dt><dd>{x(d.data.asset.role)}</dd>
                <dt>{t("ast.segment")}</dt><dd>{d.data.asset.segment}</dd>
                <dt>{t("ast.owner")}</dt><dd>{d.data.asset.owner}</dd>
                <dt>{t("ast.env")}</dt><dd>{x(d.data.asset.environment)} · {d.data.asset.os}</dd>
                <dt>{t("ast.isolatable")}</dt><dd>{d.data.asset.isolatable ? t("ast.yes") : t("ast.notIsolatable")}</dd>
                <dt>{t("ast.changeWindow")}</dt><dd>{d.data.asset.in_change_window ? t("ast.yes") : t("ast.no")}</dd>
              </dl>
              <h3>{t("ast.risk24")}</h3>
              <Sparkline points={d.data.risk_history.map((x) => x.score)} label={t("ast.risk24")} />
              {can(user?.role, "engineer") &&
                <button className="btn" onClick={() => toggleCw(d.data!.asset)}>{t("ast.toggleCw")}</button>}
              <h3>{t("nav.incidents")}</h3>
              <ul className="evidence">{d.data.incidents.map((i) => (
                <li key={i.id}><a href={`#/incidents/${i.id}`}>{x(i.attack_type ?? i.title)}</a>
                  <Badge tone={stateTone(i.state)}>{e(i.state)}</Badge></li>))}</ul>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}
