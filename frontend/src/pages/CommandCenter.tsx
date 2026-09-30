import { useMemo, useState } from "react";
import { useApp } from "../app/context";
import { useFetch, useLiveBus, useLiveTick } from "../app/hooks";
import { go } from "../app/router";
import { Badge, Empty, ErrorBox, Loading, Panel } from "../components/ui";
import { ResponseBar } from "../components/ResponseBar";
import { BreakerBanner } from "../components/BreakerBanner";
import { assetTone, fmtClock, fmtMs, pct, stateTone, TERMINAL } from "../lib/format";
import type { Key } from "../lib/i18n";
import type { Asset, IncidentSummary, LiveMessage, Report } from "../lib/types";

export function CommandCenter() {
  const { t, e, x, lang } = useApp();
  const tick = useLiveTick();
  const incs = useFetch<IncidentSummary[]>("/incidents?limit=40", [tick]);
  const kpis = useFetch<Report>("/reports/kpis?hours=24", [tick]);
  const assets = useFetch<Asset[]>("/assets", [tick]);
  const [feed, setFeed] = useState<LiveMessage[]>([]);
  const [banners, setBanners] = useState<Record<string, string>>({});

  useLiveBus((m) => {
    if (m.type === "state" || m.type === "result" || m.type === "emergency" || m.type === "command") {
      setFeed((f) => [m, ...f].slice(0, 30));
    }
    if (m.type === "result" && m.incident_id && typeof m.banner === "string") {
      setBanners((b) => ({ ...b, [m.incident_id as string]: m.banner as string }));
    }
  });

  const focus = useMemo(() => {
    const list = incs.data ?? [];
    const running = list.find((i) => !TERMINAL.has(i.state) && !["MONITOR", "PENDING_APPROVAL", "ESCALATED"].includes(i.state) && !i.hold_reason);
    if (running) return running;
    const recent = list.find((i) => i.state === "CLOSE" && i.closed_at && Date.now() - Date.parse(i.closed_at) < 60_000);
    return recent ?? list.find((i) => !TERMINAL.has(i.state)) ?? null;
  }, [incs.data]);

  const k = kpis.data?.kpis;
  const active = (incs.data ?? []).filter((i) => !TERMINAL.has(i.state)).length;
  const emergency = (incs.data ?? []).filter((i) => i.state === "ESCALATED").length;

  return (
    <div className="page">
      <BreakerBanner />
      <ResponseBar incident={focus} banner={focus ? banners[focus.id] ?? null : null} />
      <dl className="kpis">
        <div><dt>{t("kpi.active")}</dt><dd className="num">{active}</dd></div>
        <div><dt>{t("kpi.contained24")}</dt><dd className="num">{k?.auto_contained ?? "—"}</dd></div>
        <div><dt>{t("kpi.mttc")}</dt><dd className="num">{fmtMs(k?.mttc_ms_avg, lang)}</dd></div>
        <div><dt>{t("kpi.auto")}</dt><dd className="num">{pct(k?.auto_rate_pct)}</dd></div>
        <div><dt>{t("kpi.continuity")}</dt><dd className="num">{pct(k?.business_continuity_pct)}</dd></div>
        <div className={emergency ? "alert" : ""}><dt>{t("kpi.emergency")}</dt><dd className="num">{emergency}</dd></div>
      </dl>
      <div className="grid-cc">
        <Panel title={t("cc.feed")} className="span-2">
          {incs.error ? <ErrorBox error={incs.error} retry={incs.reload} /> : !incs.data ? <Loading /> :
            incs.data.length === 0 ? (
              <Empty action={<button className="btn primary" onClick={() => go("lab")}>{t("cc.openLab")}</button>}>{t("cc.empty")}</Empty>
            ) : (
              <div className="table-wrap"><table className="table">
                <thead><tr><th>{t("inc.asset")}</th><th>{t("inc.attack")}</th><th>{t("inc.state")}</th><th>{t("inc.risk")}</th><th>{t("inc.mttc")}</th></tr></thead>
                <tbody>
                  {incs.data.slice(0, 12).map((i) => (
                    <tr key={i.id} className="rowlink" onClick={() => go(`incidents/${i.id}`)}>
                      <td><a href={`#/incidents/${i.id}`}>{i.hostname ?? i.src_ip}</a></td>
                      <td>{x(i.attack_type)}</td>
                      <td><Badge tone={stateTone(i.state)}>{e(i.state)}</Badge></td>
                      <td className="num">{i.risk_score ?? "—"}</td>
                      <td className="num">{fmtMs(i.mttc_ms, lang)}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
        </Panel>
        <Panel title={t("cc.assets")}>
          {assets.error ? <ErrorBox error={assets.error} retry={assets.reload} /> : !assets.data ? <Loading /> : (
            <div className="tiermap">
              {[0, 1, 2].map((tier) => (
                <div key={tier} className="tier-row">
                  <span className="tier-label">Tier-{tier}</span>
                  <ul>
                    {assets.data!.filter((a) => a.tier === tier).map((a) => (
                      <li key={a.id} className={`cell tone-${assetTone(a.status)}`}
                          title={`${a.hostname}: ${t(`ast.${a.status}` as Key)}`}>
                        <span className="sr">{a.hostname} {t(`ast.${a.status}` as Key)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title={t("cc.events")} className="span-3">
          {feed.length === 0 ? <p className="muted small">{t("cc.noEvents")}</p> : (
            <ol className="feed">
              {feed.map((m, i) => (
                <li key={i}>
                  <span className="num muted">{fmtClock(m.at, lang)}</span>
                  <span>{m.incident_id?.slice(0, 8)}</span>
                  <span>{m.type === "state" ? e(String(m.state)) : m.type === "result" ? t(`banner.${m.banner}` as Key)
                    : m.type === "command" ? `${x(String(m.command))} ${m.ok ? "✓" : "✗"}` : x(String(m.reason ?? m.type))}</span>
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>
    </div>
  );
}
