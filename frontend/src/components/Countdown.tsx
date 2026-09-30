import { useApp } from "../app/context";
import { useNow } from "../app/hooks";
import { secondsLeft } from "../lib/format";

export function Countdown({ deadline, total, label }: { deadline: string; total: number; label: string }) {
  const { lang } = useApp();
  const now = useNow(200);
  const left = secondsLeft(deadline, now) ?? 0;
  const frac = total > 0 ? Math.min(1, left / total) : 0;
  const tone = frac > 0.5 ? "ok" : frac > 0.2 ? "warn" : "crit";
  return (
    <div className="countdown" role="timer" aria-label={label}>
      <span className="countdown-label">{label}</span>
      <span className={`countdown-num num tone-text-${tone}`}>{left.toFixed(1)}<small>{lang === "ar" ? " ث" : " s"}</small></span>
      <span className="countdown-track"><span className={`countdown-fill tone-${tone}`} style={{ inlineSize: `${frac * 100}%` }} /></span>
    </div>
  );
}
