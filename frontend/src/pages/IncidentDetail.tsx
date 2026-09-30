import { useState } from "react";
import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import { api, ApiError } from "../lib/api";
import { Badge, ErrorBox, Loading, Meter, Panel } from "../components/ui";
import { ContainmentMap } from "../components/ContainmentMap";
import { Countdown } from "../components/Countdown";
import { FactorTable } from "../components/FactorTable";
import { Lifecycle } from "../components/Lifecycle";
import { can, fmtClock, fmtMs, levelTone, riskTone, shortId, stateTone, TERMINAL } from "../lib/format";
import type { Asset, CommandResult, IncidentDetail as Detail, VerifyResult } from "../lib/types";

const ENGINEER_COMMANDS = ["ISOLATE_ASSET", "BLOCK_C2", "PROTECT_DATABASE", "REVOKE_SESSION", "RUN_VERIFICATION"];

export function IncidentDetail({ id }: { id: string }) {
  const { t, e, x, lang, user, toast } = useApp();
  const tick = useLiveTick((m) => m.incident_id === id, 250);
  const q = useFetch<Detail>(`/incidents/${id}`, [tick]);
  const assets = useFetch<Asset[]>("/assets");
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");
  const [verify, setVerify] = useState<VerifyResult | null>(null);

  const fail = (err: unknown) =>
    toast(err instanceof ApiError && err.status === 403 ? t("ui.forbidden") : x((err as Error).message), "crit");

  const act = async (path: string, json: unknown, ok: string) => {
    setBusy(true);
    try {
      await api(`/incidents/${id}/${path}`, { method: "POST", json });
      toast(ok, "ok");
      await q.reload();
    } catch (err) { fail(err); } finally { setBusy(false); }
  };

  const command = async (c: string) => {
    setBusy(true);
    try {
      const r = await api<VerifyResult & CommandResult>(`/incidents/${id}/commands`, { method: "POST", json: { command: c } });
      if (c === "RUN_VERIFICATION") {
        setVerify(r);
        if (r.passed) toast(`${t("verify.passed")}${r.resumed ? `. ${t("verify.resumed")}` : ""}`, "ok");
        else toast(t("verify.failed"), "crit");
      } else {
        toast(`${r.ok ? t("cmd.ok") : t("cmd.failed")}: ${x(c)}`, r.ok ? "ok" : "crit");
      }
      await q.reload();
    } catch (err) { fail(err); } finally { setBusy(false); }
  };

  const rollback = () => {
    if (!window.confirm(t("act.rollbackConfirm"))) return;
    void act("rollback", { reason: reason || t("act.rollbackDefault") }, t("act.rolledBack"));
  };

  if (q.error) return <div className="page"><ErrorBox error={q.error} retry={q.reload} /></div>;
  if (!q.data) return <div className="page"><Loading /></div>;
  const { incident: inc, asset } = q.data;
  const r = inc.risk;
  const terminal = TERMINAL.has(inc.state);
  const pendingCount = q.data.approvals.filter((a) => a.level === inc.pending_level).length;
  const observeStart = [...q.data.transitions].reverse().find((tr) => tr.to_state === "OBSERVE")?.at;
  const mem = inc.memory;
  const pctOf = (v?: number) => Math.round((v ?? 0) * 1000) / 10;
  const memText = !mem ? null
    : mem.applied ? `${t("inc.memory.applied")} ${pctOf(mem.score)}%`
    : mem.pattern_id ? `${t("mem.blocked")} ${x(mem.reason)}`
    : (mem.best_score ?? 0) > 0 ? t("mem.closest", { s: pctOf(mem.best_score) })
    : t("mem.noApproved");

  return (
    <div className="page detail">
      <a className="back" href="#/incidents">{t("ui.back")}</a>
      <header className="detail-head">
        <div>
          <h1>{asset?.hostname ?? inc.src_ip} <span className="muted">{x(inc.attack_type ?? inc.title)}</span></h1>
          <p className="badges">
            <Badge tone={stateTone(inc.state)}>{e(inc.state)}</Badge>
            <Badge tone={levelTone(inc.level)}>{e(inc.level)}</Badge>
            {inc.tier != null && <Badge>Tier-{inc.tier}</Badge>}
            <span className="muted small num">#{shortId(inc.id)} · {q.data.event_count} {t("inc.events")}</span>
          </p>
        </div>
        <dl className="scores">
          <div><dt>{t("inc.risk")}</dt><dd className={`num tone-text-${riskTone(inc.risk_score)}`}>{inc.risk_score ?? "—"}</dd>
            <Meter value={inc.risk_score ?? 0} tone={riskTone(inc.risk_score)} label={t("inc.risk")} /></div>
          <div><dt>{t("inc.confidence")}</dt><dd className="num">{inc.confidence != null ? `${inc.confidence}%` : "—"}</dd>
            <Meter value={inc.confidence ?? 0} tone="info" label={t("inc.confidence")} /></div>
          <div><dt>{t("inc.mttc")}</dt><dd className="num">{fmtMs(inc.mttc_ms, lang)}</dd></div>
        </dl>
      </header>

      {inc.state === "CONTAIN" && inc.deadline_at && (
        <Countdown deadline={inc.deadline_at} label={t("inc.timer.containment")}
          total={inc.decided_at ? (Date.parse(inc.deadline_at) - Date.parse(inc.decided_at)) / 1000 : 15} />
      )}
      {inc.state === "OBSERVE" && inc.observe_until && (
        <Countdown deadline={inc.observe_until} label={t("inc.timer.observation")}
          total={observeStart ? (Date.parse(inc.observe_until) - Date.parse(observeStart)) / 1000 : 60} />
      )}

      {inc.escalation_reason && inc.state === "ESCALATED" && (
        <div className="notice crit" role="alert"><p><strong>{t("inc.escalation")}:</strong> {x(inc.escalation_reason)}</p></div>
      )}
      {inc.decision?.circuit_breaker && !terminal && (
        <div className="notice warn" role="note"><p><strong>{t("cb.title")}:</strong> {t("cb.incident")}</p></div>
      )}
      {inc.hold_reason && (
        <div className="notice warn">
          <p><strong>{t("inc.hold")}:</strong> {x(inc.hold_reason)}</p>
          {can(user?.role, "analyst") && <button className="btn primary" disabled={busy}
            onClick={() => act("confirm", {}, t("act.confirmed"))}>{t("act.confirm")}</button>}
        </div>
      )}
      {inc.pending_level && !terminal && (
        <div className="notice warn">
          <p><strong>{t("inc.pending")}</strong> {e(inc.pending_level)}: <span className="num">{pendingCount}/{inc.approvals_required || 1}</span></p>
          {can(user?.role, "analyst") && <button className="btn primary" disabled={busy}
            onClick={() => act("approve", {}, t("act.approved"))}>{t("act.approve")}</button>}
        </div>
      )}

      <ContainmentMap inc={inc} asset={asset} actions={q.data.actions} assets={assets.data ?? []} />

      {can(user?.role, "engineer") && !terminal && (
        <Panel title={t("eng.title")} className={inc.state === "ESCALATED" ? "engineer hot" : "engineer"}>
          <p className="small muted">{t("eng.hint")}</p>
          <div className="btnrow">
            {ENGINEER_COMMANDS.map((c) => (
              <button key={c} className={`btn ${c === "RUN_VERIFICATION" ? "primary" : ""}`} disabled={busy} title={c}
                onClick={() => command(c)}>{x(c)}</button>
            ))}
          </div>
          {verify && (
            <div className={`verify ${verify.passed ? "pass" : "fail"}`} role="status">
              <p className="verify-head"><strong>{t("verify.title")}:</strong> {verify.passed ? t("verify.passed") : t("verify.failed")}</p>
              <ul className="checks">
                {verify.probes.map((p, i) => (
                  <li key={i} className={p.pass ? "pass" : "fail"}><span aria-hidden="true">{p.pass ? "✓" : "✗"}</span> {x(p.probe)}</li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      )}

      <Panel title={t("inc.lifecycle")}><Lifecycle state={inc.state} transitions={q.data.transitions} /></Panel>

      <div className="grid-2">
        <Panel title={t("inc.why")}>
          <ul className="reasons">{(inc.decision?.reasons ?? []).map((rs, i) => <li key={i}>{x(rs)}</li>)}</ul>
          {memText && (
            <p className={`memline ${mem?.applied ? "tone-text-mem" : "muted"}`}><strong>{t("inc.memory")}: </strong>{memText}</p>
          )}
        </Panel>
        <Panel title={t("inc.source")}>
          <dl className="kv">
            <dt>IP</dt><dd className="num">{inc.attack_source?.ip ?? "—"}</dd>
            <dt>{t("inc.country")}</dt><dd>{[inc.attack_source?.country, inc.attack_source?.city].filter(Boolean).map((v) => x(v)).join("، ") || "—"}</dd>
            <dt>ASN / {t("inc.provider")}</dt><dd>{[inc.attack_source?.asn, inc.attack_source?.provider && x(inc.attack_source.provider)].filter(Boolean).join(" / ") || "—"}</dd>
            <dt>{t("inc.reputation")}</dt><dd>{x(inc.attack_source?.reputation)}</dd>
            <dt>{t("inc.firstSeen")}</dt><dd className="num">{fmtClock(inc.attack_source?.first_seen, lang)}</dd>
            <dt>{t("inc.entry")}</dt><dd>{x(inc.entry_path)}</dd>
            <dt>MITRE</dt><dd className="num">{(inc.mitre ?? []).join(", ") || "—"}</dd>
          </dl>
        </Panel>
        {r && <Panel><FactorTable factors={r.risk_factors} total={inc.risk_score ?? 0} caption={t("inc.riskMatrix")} />
          {Object.keys(r.adjustments ?? {}).length > 0 && <p className="small muted">{t("inc.adjustments")}: {Object.entries(r.adjustments).map(([k, v]) => `${x(k)} ${v}`).join("، ")}</p>}
        </Panel>}
        {r && <Panel><FactorTable factors={r.confidence_factors} total={inc.confidence ?? 0} unit="%" caption={t("inc.confMatrix")} /></Panel>}
      </div>

      <Panel title={t("inc.actions")}>
        <div className="table-wrap">
          <table className="table compact">
            <thead><tr><th>{t("col.action")}</th><th>{t("col.target")}</th><th>{t("col.tool")}</th><th>{t("col.result")}</th><th>{t("col.attempts")}</th></tr></thead>
            <tbody>
              {q.data.actions.map((a) => (
                <tr key={a.id}>
                  <td title={a.action_type}>{x(a.action_type)}</td><td className="num">{a.target}</td><td className="muted small">{x(a.provider)}</td>
                  <td><Badge tone={a.status === "succeeded" ? "ok" : a.status === "failed" ? "crit" : "muted"}>{x(a.status)}</Badge></td>
                  <td className="num small">{a.attempts} {t("ui.attempts")} · {fmtMs(a.duration_ms, lang)}{a.manual ? ` · ${t("ui.manual")}` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid-2">
        <Panel title={t("inc.checks")}>
          <ul className="checks">
            {q.data.checks.map((c, i) => (
              <li key={i} className={c.passed ? "pass" : "fail"}><span aria-hidden="true">{c.passed ? "✓" : "✗"}</span> {x(c.check_name)}</li>
            ))}
          </ul>
        </Panel>
        <Panel title={t("inc.evidence")}>
          <p className={q.data.chain_ok ? "tone-text-ok" : "tone-text-crit"}>
            {q.data.chain_ok ? t("inc.chainOk") : `${t("inc.chainBroken")} ${q.data.chain_broken_at}`}</p>
          <ul className="evidence">{q.data.evidence.map((ev, i) => (
            <li key={i}><span>{x(ev.kind)}</span><span className="muted small num">{ev.sha256.slice(0, 16)}…</span></li>))}</ul>
          {q.data.approvals.length > 0 && <>
            <h3>{t("inc.approvals")}</h3>
            <ul className="evidence">{q.data.approvals.map((a, i) => <li key={i}><span>{a.approver}</span><span className="muted small">{e(a.level)}</span></li>)}</ul>
          </>}
        </Panel>
      </div>

      {can(user?.role, "analyst") && !terminal && (
        <Panel title={t("act.rollback")}>
          <div className="btnrow">
            <label className="grow">{t("act.rollbackReason")}
              <input value={reason} placeholder={t("act.rollbackDefault")} onChange={(ev) => setReason(ev.target.value)} /></label>
            <button className="btn danger" disabled={busy} onClick={rollback}>{t("act.rollback")}</button>
          </div>
        </Panel>
      )}

      <Panel title={t("inc.audit")}>
        <ol className="feed">
          {q.data.audit.map((a) => (
            <li key={a.id}><span className="num muted">{fmtClock(a.timestamp, lang)}</span><span>{a.actor}</span>
              <span>{x(a.action)}{a.reason ? <span className="muted"> · {x(a.reason)}</span> : null}</span></li>
          ))}
        </ol>
      </Panel>
    </div>
  );
}
