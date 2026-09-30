import { describe, expect, it } from "vitest";
import { DICTS, enumLabel, translate } from "./i18n";

describe("i18n", () => {
  it("Arabic and English have the same keys and no empty strings", () => {
    const ar = Object.keys(DICTS.ar).sort();
    const en = Object.keys(DICTS.en).sort();
    expect(ar).toEqual(en);
    for (const lang of ["ar", "en"] as const) {
      for (const [k, v] of Object.entries(DICTS[lang])) expect(v.trim().length, `${lang}:${k}`).toBeGreaterThan(0);
    }
  });
  it("falls back to English, then to the key", () => {
    expect(translate("ar", "nav.lab")).toBe("مختبر المحاكاة");
    expect(translate("en", "nav.lab")).toBe("Simulation lab");
    expect(translate("ar", "missing.key")).toBe("missing.key");
  });
  it("labels backend enums in both languages", () => {
    expect(enumLabel("ar", "ESCALATED")).toBe("طابور الطوارئ");
    expect(enumLabel("en", "FULL_ISOLATION")).toBe("Full isolation");
    expect(enumLabel("en", "SOMETHING_NEW")).toBe("something new");
    expect(enumLabel("en", null)).toBe("—");
  });
  it("covers every lab category and failure mode", () => {
    for (const c of ["network_c2", "identity", "ransomware", "cloud_k8s", "initial_access", "web_api", "data_insider", "edge_cases"]) {
      expect(translate("ar", `cat.${c}`)).not.toBe(`cat.${c}`);
    }
    for (const f of ["integration_down", "gate_fail", "ioc_return"]) expect(translate("en", `fail.${f}`)).not.toBe(`fail.${f}`);
  });
});
