/** Pure formatting and mapping helpers (unit-tested). */
import type { Lang } from "./i18n";

export const MAIN_PATH = [
  "DETECT", "UNDERSTAND", "IDENTIFY_ENTRY", "ATTRIBUTE_ASSET", "RISK", "DECIDE", "CONTAIN",
  "VERIFY", "REMEDIATE", "HARDEN", "OBSERVE", "RE_ENTRY", "LEARN", "CLOSE",
] as const;

export const PHASES = ["detecting", "analyzing", "containing", "verifying", "hardening", "recovering", "learning"] as const;
export type Phase = (typeof PHASES)[number];

const PHASE_OF: Record<string, Phase> = {
  DETECT: "detecting", UNDERSTAND: "analyzing", IDENTIFY_ENTRY: "analyzing", ATTRIBUTE_ASSET: "analyzing",
  RISK: "analyzing", DECIDE: "analyzing", CONTAIN: "containing", VERIFY: "verifying", REMEDIATE: "hardening",
  HARDEN: "hardening", OBSERVE: "recovering", RE_ENTRY: "recovering", LEARN: "learning",
};

/** Index of the active phase (0..6), 7 when neutralized, -1 when off the automated path. */
export function phaseIndex(state: string): number {
  if (state === "CLOSE") return PHASES.length;
  const p = PHASE_OF[state];
  return p ? PHASES.indexOf(p) : -1;
}

export const TERMINAL = new Set(["CLOSE", "ROLLED_BACK"]);

export type Tone = "ok" | "warn" | "crit" | "info" | "mem" | "muted";

export function stateTone(state: string): Tone {
  if (state === "CLOSE") return "ok";
  if (state === "ESCALATED") return "crit";
  if (state === "PENDING_APPROVAL" || state === "MONITOR") return "warn";
  if (state === "ROLLED_BACK") return "muted";
  return "info";
}

export function levelTone(level: string | null | undefined): Tone {
  switch (level) {
    case "FULL_ISOLATION": return "crit";
    case "SURGICAL": case "EMERGENCY_RESTRICT": return "warn";
    case "RESTRICT": case "COMPENSATING": return "info";
    default: return "muted";
  }
}

export function assetTone(status: string): Tone {
  if (status === "healthy") return "ok";
  if (status === "isolated") return "crit";
  if (status === "quarantined" || status === "restricted") return "warn";
  return "info";
}

export function riskTone(score: number | null | undefined): Tone {
  if (score == null) return "muted";
  if (score >= 85) return "crit";
  if (score >= 60) return "warn";
  return "ok";
}

export function fmtMs(ms: number | null | undefined, lang: Lang): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ${lang === "ar" ? "مللي ث" : "ms"}`;
  const unit = lang === "ar" ? "ث" : "s";
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} ${unit}`;
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return lang === "ar" ? `${m} د ${s} ث` : `${m} m ${s} s`;
}

/** Seconds left until an ISO deadline (never negative); null when there is no deadline. */
export function secondsLeft(deadlineIso: string | null | undefined, nowMs: number = Date.now()): number | null {
  if (!deadlineIso) return null;
  const t = Date.parse(deadlineIso);
  if (Number.isNaN(t)) return null;
  return Math.max(0, (t - nowMs) / 1000);
}

export function fmtClock(iso: string | null | undefined, lang: Lang): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString(lang === "ar" ? "ar-KW-u-nu-latn" : "en-GB",
    { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function fmtDateTime(iso: string | null | undefined, lang: Lang): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(lang === "ar" ? "ar-KW-u-nu-latn" : "en-GB",
    { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function pct(v: number | null | undefined): string {
  return v == null ? "—" : `${Math.round(v)}%`;
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/** Role ladder mirrors the backend RBAC. */
export const ROLES = ["viewer", "analyst", "engineer", "admin"] as const;
export type Role = (typeof ROLES)[number];

export function can(role: string | undefined, minimum: Role): boolean {
  const r = ROLES.indexOf((role ?? "viewer") as Role);
  return r >= ROLES.indexOf(minimum);
}
