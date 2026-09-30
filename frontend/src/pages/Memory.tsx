import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import { api } from "../lib/api";
import { Badge, Empty, ErrorBox, Loading } from "../components/ui";
import { can, fmtDateTime } from "../lib/format";
import type { Key } from "../lib/i18n";
import type { Pattern } from "../lib/types";
import { trList } from "../lib/tr";

export function Memory() {
  const { t, e, x, lang, user, toast } = useApp();
  const tick = useLiveTick((m) => m.type === "pattern" || (m.type === "result" && String(m.banner).startsWith("RESPONSE")));
  const q = useFetch<{ threshold: number; patterns: Pattern[] }>("/memory/patterns", [tick]);
  const review = async (p: Pattern, approve: boolean) => {
    try {
      await api(`/memory/patterns/${p.id}/${approve ? "approve" : "reject"}`, { method: "POST", json: {} });
      toast(t("mem.reviewed"), "ok");
      await q.reload();
    } catch (err) { toast(x((err as Error).message), "crit"); }
  };
  if (q.error) return <div className="page"><ErrorBox error={q.error} retry={q.reload} /></div>;
  if (!q.data) return <div className="page"><Loading /></div>;
  return (
    <div className="page">
      <header className="page-head"><h1>{t("nav.memory")}</h1>
        <span className="muted">{t("mem.threshold")}: <span className="num">{Math.round(q.data.threshold * 100)}%</span></span></header>
      <p className="lead">{t("mem.hint")}</p>
      {q.data.patterns.length === 0 ? <Empty>{t("mem.empty")}</Empty> : (
        <ul className="patterns">
          {q.data.patterns.map((p) => {
            const fp = p.fingerprint as Record<string, unknown>;
            return (
              <li key={p.id} className={`pattern st-${p.status}`}>
                <header>
                  <Badge tone={p.status === "APPROVED" ? "mem" : p.status === "REJECTED" ? "muted" : "warn"}>{t(`mem.${p.status}` as Key)}</Badge>
                  <strong>{x(String(fp.attack_type))}</strong>
                  <span className="muted">{x(String(fp.asset_role))} · Tier-{String(fp.tier)} · {e(p.level)}</span>
                  <span className="muted small num">{fmtDateTime(p.created_at, lang)}</span>
                </header>
                <p className="small"><span className="muted">{t("mem.commands")}:</span> <span>{trList(lang, p.commands)}</span></p>
                <p className="small muted">MITRE {(fp.mitre as string[] | undefined)?.join(", ") || "—"} · {(fp.rules as string[] | undefined)?.join(", ")}</p>
                <p className="small">{t("mem.hits")}: <span className="num">{p.hits}</span> · {t("mem.occurrences")}: <span className="num">{p.occurrences}</span>
                  {p.approved_by && <span className="muted"> · {p.approved_by}</span>}</p>
                {p.status === "PENDING_VALIDATION" && can(user?.role, "engineer") && (
                  <div className="btnrow">
                    <button className="btn primary" onClick={() => review(p, true)}>{t("mem.approve")}</button>
                    <button className="btn" onClick={() => review(p, false)}>{t("mem.reject")}</button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
