import { useState } from "react";
import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import { go } from "../app/router";
import { Badge, Empty, ErrorBox, Loading } from "../components/ui";
import { fmtDateTime, fmtMs, levelTone, riskTone, stateTone } from "../lib/format";
import type { IncidentSummary } from "../lib/types";

const FILTERS = ["", "CONTAIN", "VERIFY", "OBSERVE", "PENDING_APPROVAL", "ESCALATED", "MONITOR", "CLOSE", "ROLLED_BACK"];

export function IncidentList({ state = "", emptyText }: { state?: string; emptyText?: string }) {
  const { t, e, x, lang } = useApp();
  const tick = useLiveTick();
  const q = useFetch<IncidentSummary[]>(`/incidents?limit=200${state ? `&state=${state}` : ""}`, [tick]);
  if (q.error) return <ErrorBox error={q.error} retry={q.reload} />;
  if (!q.data) return <Loading />;
  if (!q.data.length) return <Empty>{emptyText ?? t("inc.empty")}</Empty>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr><th>{t("inc.asset")}</th><th>{t("inc.attack")}</th><th>{t("inc.tier")}</th><th>{t("inc.state")}</th>
            <th>{t("inc.level")}</th><th>{t("inc.risk")}</th><th>{t("inc.confidence")}</th><th>{t("inc.mttc")}</th>
            <th>{t("inc.detected")}</th></tr>
        </thead>
        <tbody>
          {q.data.map((i) => (
            <tr key={i.id} className="rowlink" onClick={() => go(`incidents/${i.id}`)}>
              <td><a href={`#/incidents/${i.id}`}>{i.hostname ?? i.src_ip}</a>
                {i.escalation_reason && <span className="muted small block">{x(i.escalation_reason)}</span>}
                {i.hold_reason && <span className="tone-text-warn small block">{x(i.hold_reason)}</span>}</td>
              <td>{x(i.attack_type)}</td>
              <td className="num">{i.tier ?? "—"}</td>
              <td><Badge tone={stateTone(i.state)}>{e(i.state)}</Badge></td>
              <td><Badge tone={levelTone(i.level)}>{e(i.level)}</Badge></td>
              <td className={`num tone-text-${riskTone(i.risk_score)}`}>{i.risk_score ?? "—"}</td>
              <td className="num">{i.confidence != null ? `${i.confidence}%` : "—"}</td>
              <td className="num">{fmtMs(i.mttc_ms, lang)}</td>
              <td className="num small">{fmtDateTime(i.detected_at, lang)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Incidents() {
  const { t, e } = useApp();
  const [state, setState] = useState("");
  return (
    <div className="page">
      <header className="page-head">
        <h1>{t("nav.incidents")}</h1>
        <label className="inline">{t("inc.filter")}
          <select value={state} onChange={(ev) => setState(ev.target.value)}>
            {FILTERS.map((f) => <option key={f} value={f}>{f ? e(f) : t("ui.all")}</option>)}
          </select>
        </label>
      </header>
      <IncidentList state={state} />
    </div>
  );
}

export function Emergency() {
  const { t } = useApp();
  return (
    <div className="page">
      <header className="page-head"><h1>{t("nav.emergency")}</h1></header>
      <p className="lead">{t("emg.hint")}</p>
      <IncidentList state="ESCALATED" emptyText={t("emg.empty")} />
    </div>
  );
}
