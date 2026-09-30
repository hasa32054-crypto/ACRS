import { useMemo, useState } from "react";
import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import { ErrorBox, Loading } from "../components/ui";
import { fmtDateTime } from "../lib/format";
import type { AuditRow } from "../lib/types";

export function Audit() {
  const { t, x, lang } = useApp();
  const tick = useLiveTick(() => true, 1500);
  const q = useFetch<AuditRow[]>("/audit?limit=500", [tick]);
  const [needle, setNeedle] = useState("");
  const rows = useMemo(() => {
    const n = needle.trim().toLowerCase();
    return (q.data ?? []).filter((a) => !n || `${a.actor} ${a.action} ${x(a.action)} ${a.target} ${a.reason} ${x(a.reason)}`
      .toLowerCase().includes(n));
  }, [q.data, needle, x]);
  return (
    <div className="page">
      <header className="page-head"><h1>{t("nav.audit")}</h1>
        <label className="inline">{t("aud.filter")}<input type="search" value={needle} onChange={(e) => setNeedle(e.target.value)} /></label></header>
      <p className="lead">{t("aud.title")}</p>
      {q.error ? <ErrorBox error={q.error} retry={q.reload} /> : !q.data ? <Loading /> : (
        <div className="table-wrap">
          <table className="table compact">
            <thead><tr><th>{t("aud.time")}</th><th>{t("aud.actor")}</th><th>{t("aud.action")}</th><th>{t("aud.target")}</th><th>{t("aud.reason")}</th></tr></thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id}>
                  <td className="num small">{fmtDateTime(a.timestamp, lang)}</td>
                  <td className={a.actor === "ACRS" ? "tone-text-info" : ""}>{a.actor}</td>
                  <td title={a.action}>{x(a.action)}</td>
                  <td>{a.target ?? "—"}{a.incident_id && <a className="small block" href={`#/incidents/${a.incident_id}`}>#{a.incident_id.slice(0, 8)}</a>}</td>
                  <td className="small">{a.reason ? x(a.reason) : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
