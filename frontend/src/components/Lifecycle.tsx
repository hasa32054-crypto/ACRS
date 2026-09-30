import { useApp } from "../app/context";
import { MAIN_PATH } from "../lib/format";
import type { Transition } from "../lib/types";

/** 14-stage path. Stages are a real sequence, so they are numbered. */
export function Lifecycle({ state, transitions }: { state: string; transitions: Transition[] }) {
  const { e, t } = useApp();
  const visited = new Set(transitions.map((x) => x.to_state));
  const current = MAIN_PATH.indexOf(state as (typeof MAIN_PATH)[number]);
  const off = current < 0;
  return (
    <div>
      <ol className="lifecycle" aria-label={t("inc.lifecycle")}>
        {MAIN_PATH.map((s, i) => {
          const cls = s === state ? "now" : visited.has(s) ? "past" : "future";
          return (
            <li key={s} className={cls} aria-current={s === state ? "step" : undefined}>
              <span className="lc-n num">{i + 1}</span><span className="lc-name">{e(s)}</span>
            </li>
          );
        })}
      </ol>
      {off && <p className={`lc-side tone-text-${state === "ESCALATED" ? "crit" : "warn"}`}>{e(state)}</p>}
    </div>
  );
}
