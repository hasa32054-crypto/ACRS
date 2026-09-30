import { useApp } from "../app/context";
import { useNow } from "../app/hooks";
import { go } from "../app/router";
import { PHASES, phaseIndex, secondsLeft } from "../lib/format";
import type { Key } from "../lib/i18n";
import type { IncidentSummary } from "../lib/types";

/** The Autonomous Response Bar: the one animated element of the console. */
export function ResponseBar({ incident, banner }: { incident: IncidentSummary | null; banner: string | null }) {
  const { t, e, x, lang } = useApp();
  const now = useNow(200);
  if (!incident) {
    return (
      <section className="rbar idle" aria-label={t("bar.idle")}>
        <p className="rbar-status">{t("bar.idle")}</p>
        <ol className="rbar-track">{PHASES.map((p) => <li key={p} className="seg"><span>{t(`bar.${p}` as Key)}</span></li>)}</ol>
      </section>
    );
  }
  const idx = phaseIndex(incident.state);
  const done = incident.state === "CLOSE";
  const escalated = incident.state === "ESCALATED";
  const waiting = incident.state === "PENDING_APPROVAL" || incident.state === "MONITOR" || !!incident.hold_reason;
  const left = incident.state === "CONTAIN" ? secondsLeft(incident.deadline_at, now) : null;
  const status = done ? t("bar.neutralized") : escalated ? t("bar.escalated") : waiting ? t("bar.waiting")
    : idx >= 0 ? `${t(`bar.${PHASES[idx]}` as Key)}…` : e(incident.state);
  const cls = done ? "done" : escalated ? "crit" : waiting ? "wait" : "run";
  return (
    <section className={`rbar ${cls}`} aria-live="polite">
      <div className="rbar-top">
        <button className="rbar-title linklike" onClick={() => go(`incidents/${incident.id}`)}>
          {incident.hostname ?? incident.src_ip}
          <span className="muted"> {x(incident.attack_type ?? incident.title)}</span>
        </button>
        {left != null && <span className="rbar-timer num" role="timer" aria-label={t("inc.timer.containment")}>
          {left.toFixed(1)}<small>{lang === "ar" ? "ث" : "s"}</small></span>}
      </div>
      <p className="rbar-status">{status}</p>
      <ol className="rbar-track">
        {PHASES.map((p, i) => (
          <li key={p} className={`seg ${i < idx || done ? "past" : ""} ${i === idx && !done ? "now" : ""}`}
              aria-current={i === idx && !done ? "step" : undefined}>
            <span>{t(`bar.${p}` as Key)}</span>
          </li>
        ))}
      </ol>
      {banner && <p className="rbar-banner" key={banner}>{t(`banner.${banner}` as Key)}</p>}
    </section>
  );
}
