import type { ReactNode } from "react";
import { useApp } from "../app/context";
import type { Tone } from "../lib/format";

export function Badge({ tone = "muted", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return <span className={`badge tone-${tone}`} title={title}>{children}</span>;
}

export function Loading() {
  const { t } = useApp();
  return <p className="state-msg" role="status">{t("ui.loading")}</p>;
}

export function ErrorBox({ error, retry }: { error: Error; retry?: () => void }) {
  const { t } = useApp();
  return (
    <div className="state-msg error" role="alert">
      <p>{t("ui.error")}</p>
      <p className="muted small">{error.message}</p>
      {retry && <button className="btn" onClick={retry}>{t("ui.retry")}</button>}
    </div>
  );
}

export function Empty({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return <div className="state-msg empty"><p>{children}</p>{action}</div>;
}

export function Panel({ title, children, aside, className = "" }:
  { title?: ReactNode; children: ReactNode; aside?: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || aside) && <header className="panel-head">{title && <h2>{title}</h2>}{aside}</header>}
      {children}
    </section>
  );
}

export function Meter({ value, tone, label }: { value: number; tone: Tone; label: string }) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className="meter" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v)} aria-label={label}>
      <div className={`meter-fill tone-${tone}`} style={{ inlineSize: `${v}%` }} />
    </div>
  );
}

export function Bars({ data, label }: { data: Record<string, number>; label: (k: string) => string }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (!entries.length) return <p className="muted small">—</p>;
  return (
    <ul className="bars">
      {entries.map(([k, v]) => (
        <li key={k}>
          <span className="bars-label">{label(k)}</span>
          <span className="bars-track"><span className="bars-fill" style={{ inlineSize: `${(v / max) * 100}%` }} /></span>
          <span className="bars-value num">{v}</span>
        </li>
      ))}
    </ul>
  );
}

export function Sparkline({ points, label }: { points: number[]; label: string }) {
  if (points.length < 2) return <p className="muted small">—</p>;
  const w = 240, h = 48;
  const max = 100;
  const d = points.map((p, i) => `${(i / (points.length - 1)) * w},${h - (p / max) * (h - 4) - 2}`).join(" ");
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label} preserveAspectRatio="none">
      <line x1="0" x2={w} y1={h - 0.6 * (h - 4) - 2} y2={h - 0.6 * (h - 4) - 2} className="spark-guide" />
      <polyline points={d} className="spark-line" />
    </svg>
  );
}
