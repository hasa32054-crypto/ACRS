import type { Action, Asset, Incident } from "./types";

/** Commands that stop the host from reaching the internet (same rule as the backend verification probes). */
const EGRESS = ["RESTRICT_NETWORK", "ISOLATE_ASSET", "APPLY_MICROSEGMENTATION"];
/** Commands that stop the host from reaching internal systems. */
const LATERAL = ["ISOLATE_ASSET", "APPLY_MICROSEGMENTATION", "RESTRICT_SEGMENT_LATERAL"];
const PRE_CONTAIN = new Set(["DETECT", "UNDERSTAND", "IDENTIFY_ENTRY", "ATTRIBUTE_ASSET", "RISK", "DECIDE"]);

export type Verdict = "waiting" | "running" | "isolated" | "restricted" | "failed" | "pending" | "monitor" | "restored" | "rolledback";

export interface MapModel {
  verdict: Verdict; egressCut: boolean; c2Blocked: boolean; lateralCut: boolean;
  reach: string[]; sibling: string | null;
}

/** Pure model of what the map shows (unit-tested). */
export function containmentModel(inc: Incident, asset: Asset | null, actions: Action[], assets: Asset[]): MapModel {
  // "released" = applied, then lifted when the host re-entered the network; it still counts as having happened.
  const done = inc.state === "ROLLED_BACK" ? ["succeeded"] : ["succeeded", "released"];
  const ok = new Set(actions.filter((a) => done.includes(a.status)).map((a) => a.action_type));
  const egressCut = EGRESS.some((c) => ok.has(c));
  const c2Blocked = egressCut || ok.has("BLOCK_C2");
  const lateralCut = LATERAL.some((c) => ok.has(c));
  const byIp = new Map(assets.map((a) => [a.ip, a.hostname]));
  const self = asset?.hostname;
  const peers = inc.risk?.blast_radius?.peers ?? [];
  const sibling = inc.level === "SURGICAL" && asset
    ? assets.find((a) => a.role === asset.role && a.hostname !== self && a.tier === asset.tier)?.hostname ?? null : null;
  const reach = [...new Set([...(asset?.dependents ?? []), ...peers.map((p) => byIp.get(p) ?? p)])]
    .filter((h) => h !== self && h !== sibling).slice(0, 5);

  let verdict: Verdict;
  const s = inc.state;
  if (s === "ROLLED_BACK") verdict = "rolledback";
  else if (s === "CLOSE") verdict = "restored";
  else if (s === "MONITOR") verdict = "monitor";
  else if (s === "PENDING_APPROVAL") verdict = "pending";
  else if (PRE_CONTAIN.has(s)) verdict = "waiting";
  else if (egressCut && lateralCut) verdict = "isolated";
  else if (egressCut && (inc.level === "RESTRICT" || inc.level === "COMPENSATING")) verdict = "restricted";
  else if (egressCut && !reach.length) verdict = "isolated";
  else if (s === "ESCALATED") verdict = "failed";
  else verdict = "running";
  return { verdict, egressCut, c2Blocked, lateralCut, reach, sibling };
}

