import { useApp } from "../app/context";
import type { Key } from "../lib/i18n";
import { containmentModel } from "../lib/containment";
import type { Action, Asset, Incident } from "../lib/types";

type Link = "active" | "spread" | "cut" | "allowed" | "restored";

const W = 720, H = 380;

export function ContainmentMap({ inc, asset, actions, assets }:
  { inc: Incident; asset: Asset | null; actions: Action[]; assets: Asset[] }) {
  const { t, x, e, lang } = useApp();
  const m = containmentModel(inc, asset, actions, assets);
  const rtl = lang === "ar";
  const X = (v: number) => (rtl ? W - v : v);
  const restored = m.verdict === "restored" || m.verdict === "rolledback";

  const hostToFw: Link = restored ? "restored" : m.egressCut ? "cut" : "active";
  const fwToAttacker: Link = m.verdict === "rolledback" ? "active" : m.c2Blocked || m.verdict === "restored" ? "cut" : "active";
  const lateral: Link = restored ? "restored" : m.lateralCut ? "cut" : "spread";

  const hostTone = restored ? "ok" : m.verdict === "isolated" ? "ok" : m.verdict === "failed" ? "crit"
    : m.verdict === "restricted" ? "warn" : m.egressCut || m.lateralCut ? "info" : "crit";
  const host = { x: 420, y: 150 };
  const fw = { x: 238, y: 150 };
  const attacker = { x: 66, y: 150 };
  const soc = { x: 238, y: 318 };
  const reachX = 628;
  const reachY = (i: number, n: number) => (n === 1 ? 150 : 40 + (i * 260) / Math.max(1, n - 1));
  const attackerIp = inc.attack_source?.ip ?? "—";
  const country = inc.attack_source?.country ? x(inc.attack_source.country) : "";

  const tone = { waiting: "info", running: "info", isolated: "ok", restricted: "warn", failed: "crit", pending: "warn",
    monitor: "muted", restored: "ok", rolledback: "muted" }[m.verdict];
  const icon = { waiting: "…", running: "…", isolated: "✓", restricted: "◐", failed: "✗", pending: "!", monitor: "·",
    restored: "✓", rolledback: "↺" }[m.verdict];
  const cutCount = m.lateralCut || restored ? m.reach.length : 0;

  return (
    <section className="panel cmap" aria-label={t("map.title")}>
      <header className="panel-head"><h2>{t("map.title")}</h2>
        {m.reach.length > 0 && <span className="muted small">{t("map.reachCount")} <span className="num">{m.reach.length}</span> {t("map.systems")}
          {!restored && <> · <span className="num">{cutCount}</span> {t("map.cut")}</>}</span>}
      </header>
      <p className={`cmap-verdict tone-${tone}`} role="status"><span aria-hidden="true">{icon}</span> {t(`map.v.${m.verdict}` as Key)}</p>
      <svg viewBox={`0 0 ${W} ${H}`} className="cmap-svg" role="img" aria-label={t(`map.v.${m.verdict}` as Key)}>
        <Edge a={{ x: X(host.x), y: host.y }} b={{ x: X(fw.x), y: fw.y }} kind={hostToFw} />
        <Edge a={{ x: X(fw.x), y: fw.y }} b={{ x: X(attacker.x), y: attacker.y }} kind={fwToAttacker} />
        {m.reach.map((r, i) => (
          <Edge key={r} a={{ x: X(host.x), y: host.y }} b={{ x: X(reachX), y: reachY(i, m.reach.length) }} kind={lateral} />
        ))}
        {!restored && <Edge a={{ x: X(soc.x), y: soc.y }} b={{ x: X(host.x), y: host.y }} kind="allowed" />}
        {m.sibling && <Edge a={{ x: X(host.x), y: host.y }} b={{ x: X(host.x), y: 320 }} kind={lateral === "spread" ? "spread" : "cut"} />}

        <Node x={X(attacker.x)} y={attacker.y} w={112} tone="crit" title={t("map.attacker")} sub={attackerIp} sub2={country} />
        <Node x={X(fw.x)} y={fw.y} w={116} tone="muted" title={t("map.perimeter")} sub={m.c2Blocked ? x("BLOCK_C2") : ""} />
        <Node x={X(host.x)} y={host.y} w={158} h={70} tone={hostTone} strong title={asset?.hostname ?? inc.src_ip}
          sub={t("map.infected")} sub2={inc.level ? e(inc.level) : ""} />
        {m.reach.map((r, i) => (
          <Node key={r} x={X(reachX)} y={reachY(i, m.reach.length)} w={140}
            tone={restored || m.lateralCut ? "ok" : "warn"} title={r} />
        ))}
        {m.reach.length > 0 && <text x={X(reachX)} y={H - 8} className="cmap-cap" textAnchor="middle">{t("map.reach")}</text>}
        {!restored && <Node x={X(soc.x)} y={soc.y} w={130} tone="info" title={t("map.soc")} sub="soc-jump-01" />}
        {m.sibling && <Node x={X(host.x)} y={330} w={170} tone="ok" title={m.sibling} sub={t("map.sibling")} />}
      </svg>
      <ul className="cmap-paths" aria-label={t("map.title")}>
        <PathRow label={`${t("map.attacker")} ${attackerIp}`} kind={hostToFw === "cut" || fwToAttacker === "cut" ? "cut" : hostToFw} />
        {m.reach.map((r) => <PathRow key={r} label={r} kind={lateral} />)}
        {m.sibling && <PathRow label={`${m.sibling} (${t("map.sibling")})`} kind={lateral === "spread" ? "spread" : "cut"} />}
      </ul>
      <ul className="cmap-legend small">
        <li><span className="lg lg-active" />{t("map.legend.active")}</li>
        <li><span className="lg lg-spread" />{t("map.legend.spread")}</li>
        <li><span className="lg lg-cut">✕</span>{t("map.legend.cut")}</li>
        <li><span className="lg lg-allowed" />{t("map.legend.allowed")}</li>
        <li><span className="lg lg-restored" />{t("map.legend.restored")}</li>
      </ul>
    </section>
  );
}

function PathRow({ label, kind }: { label: string; kind: Link }) {
  const { t } = useApp();
  const word = kind === "cut" ? t("map.cut") : kind === "restored" ? t("map.legend.restored") : t("map.open");
  const tone = kind === "cut" || kind === "restored" ? "ok" : kind === "active" ? "crit" : "warn";
  return (
    <li><span>{label}</span><span className={`badge tone-${tone}`}>{kind === "cut" ? "✕ " : ""}{word}</span></li>
  );
}

function Edge({ a, b, kind }: { a: { x: number; y: number }; b: { x: number; y: number }; kind: Link }) {
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
  return (
    <g className={`edge edge-${kind}`}>
      <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
      {kind === "cut" && (
        <g className="edge-cut-mark" transform={`translate(${mx} ${my})`}>
          <circle r="11" />
          <path d="M-5 -5 L5 5 M5 -5 L-5 5" />
        </g>
      )}
    </g>
  );
}

function Node({ x, y, w, h: hIn, tone, title, sub, sub2, strong }:
  { x: number; y: number; w: number; h?: number; tone: string; title: string; sub?: string; sub2?: string; strong?: boolean }) {
  const h = hIn ?? (sub2 ? 64 : 52);
  return (
    <g className={`node tone-${tone} ${strong ? "strong" : ""}`} transform={`translate(${x - w / 2} ${y - h / 2})`}>
      <rect width={w} height={h} rx="6" className="node-base" />
      <rect width={w} height={h} rx="6" className="node-tint" />
      <text x={w / 2} y={sub ? (sub2 ? 19 : 22) : h / 2 + 5} textAnchor="middle" className="node-title">{title}</text>
      {sub && <text x={w / 2} y={sub2 ? 36 : 40} textAnchor="middle" className="node-sub">{sub}</text>}
      {sub2 && <text x={w / 2} y={52} textAnchor="middle" className="node-sub">{sub2}</text>}
    </g>
  );
}
