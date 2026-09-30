import { describe, expect, it } from "vitest";
import { containmentModel } from "./containment";
import type { Action, Asset, Incident } from "./types";

const asset = (h: string, ip: string, role = "hr-app", tier = 1, dependents: string[] = []): Asset => ({
  id: 1, hostname: h, ip, tier, role, segment: "hr-apps", owner: "HR", isolatable: true, criticality: "high", os: "x",
  environment: "on-prem", in_change_window: false, dependents, status: "healthy", network_stage: null, current_risk: 0,
});
const HR1 = asset("HR-APP-01", "10.20.1.11", "hr-app", 1, ["HR-DB-01", "HR-API-GW"]);
const ALL = [HR1, asset("HR-APP-02", "10.20.1.12"), asset("HR-DB-01", "10.20.2.21", "database"), asset("WS-HR-011", "10.40.1.11", "workstation", 2)];
const act = (name: string, status = "succeeded"): Action => ({ id: name, action_type: name, layer: "network", target: "x",
  status, attempts: 1, manual: false, provider: "p", duration_ms: 5, level: "SURGICAL", cycle: 1 });
const inc = (state: string, level = "SURGICAL", peers: string[] = []): Incident => ({
  id: "i", state, title: "t", src_ip: "10.20.1.11", detected_at: "2026-09-22T10:00:00Z", level,
  risk: { risk_factors: [], confidence_factors: [], adjustments: {}, blast_radius: { peers } },
});

describe("containment map model", () => {
  it("shows a failed isolation when the tool never applied the host-side commands", () => {
    const m = containmentModel(inc("ESCALATED"), HR1, [act("BLOCK_C2"), act("RESTRICT_NETWORK", "failed")], ALL);
    expect(m.verdict).toBe("failed");
    expect(m.c2Blocked).toBe(true);       // blocked at the perimeter…
    expect(m.egressCut).toBe(false);      // …but the host itself is still connected
    expect(m.lateralCut).toBe(false);
  });
  it("shows isolated once egress and lateral paths are cut", () => {
    const m = containmentModel(inc("VERIFY"), HR1, [act("RESTRICT_NETWORK"), act("ISOLATE_ASSET")], ALL);
    expect(m.verdict).toBe("isolated");
    expect(m.reach).toEqual(["HR-DB-01", "HR-API-GW"]);
    expect(m.sibling).toBe("HR-APP-02");  // surgical: the redundant node keeps serving
  });
  it("shows restricted for the medium band (internet cut, internal allowed)", () => {
    const m = containmentModel(inc("VERIFY", "RESTRICT"), HR1, [act("RESTRICT_NETWORK")], ALL);
    expect(m.verdict).toBe("restricted");
    expect(m.sibling).toBeNull();
    const lone = asset("DEV-BUILD-07", "10.50.1.7", "build-server", 2);   // no dependents: still "restricted", not "isolated"
    expect(containmentModel(inc("VERIFY", "RESTRICT"), lone, [act("RESTRICT_NETWORK")], [lone]).verdict).toBe("restricted");
  });
  it("maps contacted internal IPs to hostnames and counts released actions after re-entry", () => {
    const m = containmentModel(inc("OBSERVE", "FULL_ISOLATION", ["10.40.1.11", "10.9.9.9"]), HR1,
      [act("ISOLATE_ASSET", "released")], ALL);
    expect(m.reach).toEqual(["HR-DB-01", "HR-API-GW", "WS-HR-011", "10.9.9.9"]);
    expect(m.verdict).toBe("isolated");
  });
  it("covers the other lifecycle outcomes", () => {
    expect(containmentModel(inc("DECIDE"), HR1, [], ALL).verdict).toBe("waiting");
    expect(containmentModel(inc("CONTAIN"), HR1, [act("BLOCK_C2")], ALL).verdict).toBe("running");
    expect(containmentModel(inc("CLOSE"), HR1, [act("ISOLATE_ASSET", "released")], ALL).verdict).toBe("restored");
    expect(containmentModel(inc("ROLLED_BACK"), HR1, [act("ISOLATE_ASSET", "rolled_back")], ALL).verdict).toBe("rolledback");
    expect(containmentModel(inc("PENDING_APPROVAL"), HR1, [], ALL).verdict).toBe("pending");
    expect(containmentModel(inc("MONITOR", "MONITOR"), HR1, [], ALL).verdict).toBe("monitor");
  });
});
