import { useApp } from "../app/context";
import { useFetch, useLiveTick } from "../app/hooks";
import type { Guards } from "../lib/types";

/** Explains, before it surprises anyone, why new incidents wait for a human. */
export function BreakerBanner() {
  const { t } = useApp();
  const tick = useLiveTick((m) => m.type === "state", 800);
  const g = useFetch<Guards>("/system/guards", [tick]);
  const cb = g.data?.circuit_breaker;
  if (!cb?.tripped) return null;
  return (
    <div className="notice warn" role="status">
      <p><strong>{t("cb.title")}:</strong> {t("cb.body", { n: cb.open_auto_containments, max: cb.limit })}</p>
    </div>
  );
}
