import { describe, expect, it } from "vitest";
import { can, fmtMs, MAIN_PATH, PHASES, phaseIndex, riskTone, secondsLeft, stateTone } from "./format";
import { parseHash } from "../app/router";

describe("response bar phases", () => {
  it("maps every automated state to a phase and CLOSE to neutralized", () => {
    for (const s of MAIN_PATH.slice(0, -1)) expect(phaseIndex(s)).toBeGreaterThanOrEqual(0);
    expect(phaseIndex("DETECT")).toBe(0);
    expect(phaseIndex("CONTAIN")).toBe(PHASES.indexOf("containing"));
    expect(phaseIndex("CLOSE")).toBe(PHASES.length);
    expect(phaseIndex("ESCALATED")).toBe(-1);
  });
  it("keeps the phases in lifecycle order", () => {
    const order = MAIN_PATH.slice(0, -1).map(phaseIndex);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });
});

describe("formatting", () => {
  it("formats durations", () => {
    expect(fmtMs(450, "en")).toBe("450 ms");
    expect(fmtMs(2500, "en")).toBe("2.5 s");
    expect(fmtMs(75_000, "en")).toBe("1 m 15 s");
    expect(fmtMs(null, "ar")).toBe("—");
  });
  it("counts down to a deadline and never goes negative", () => {
    const now = Date.parse("2026-09-22T10:00:00Z");
    expect(secondsLeft("2026-09-22T10:00:07Z", now)).toBe(7);
    expect(secondsLeft("2026-09-22T09:59:00Z", now)).toBe(0);
    expect(secondsLeft(null, now)).toBeNull();
  });
  it("uses tones that match the policy bands", () => {
    expect(riskTone(94)).toBe("crit");
    expect(riskTone(70)).toBe("warn");
    expect(riskTone(20)).toBe("ok");
    expect(stateTone("ESCALATED")).toBe("crit");
    expect(stateTone("CLOSE")).toBe("ok");
  });
});

describe("rbac and routing", () => {
  it("follows the viewer < analyst < engineer < admin ladder", () => {
    expect(can("viewer", "analyst")).toBe(false);
    expect(can("analyst", "analyst")).toBe(true);
    expect(can("engineer", "analyst")).toBe(true);
    expect(can("analyst", "engineer")).toBe(false);
    expect(can(undefined, "viewer")).toBe(true);
  });
  it("parses hash routes", () => {
    expect(parseHash("#/incidents/abc")).toEqual({ page: "incidents", param: "abc" });
    expect(parseHash("")).toEqual({ page: "", param: null });
    expect(parseHash("#/lab")).toEqual({ page: "lab", param: null });
  });
});
