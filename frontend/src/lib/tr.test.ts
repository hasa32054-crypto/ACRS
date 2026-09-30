import { describe, expect, it } from "vitest";
import fixture from "./backend-strings.fixture.json";
import { tr, trList } from "./tr";

/** Tokens that legitimately stay in Latin script: hosts, IPs, MITRE IDs, protocols and product names. */
const ALLOWED = new Set(["tier", "dns", "api", "lsass", "smb", "rdp", "erp", "vpn", "aws", "kubernetes", "misp", "opencti",
  "tor", "amazon", "acrs", "simulated", "palo", "alto", "illumio", "cisco", "ise", "entra", "okta", "istio", "infoblox",
  "rpz", "iam", "db", "firewall", "edr", "sg", "perimeter", "fw", "unknown",
  "analyst", "engineer", "admin", "viewer", "connector"]);  // usernames

function leftoverEnglish(text: string): string[] {
  return text
    .replace(/\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/g, " ")
    .split(/[\s,،:()«»\[\]/]+/)
    .filter((w) => /^[A-Za-z]{3,}$/.test(w))            // plain words only: hosts/IDs contain digits, dots, dashes
    .filter((w) => !(w === w.toUpperCase()))            // ACRONYMS and command codes are fine
    .filter((w) => !/[A-Z].*[A-Z]/.test(w))             // CamelCase API names (CreateAccessKey)
    .filter((w) => !ALLOWED.has(w.toLowerCase()));
}

describe("backend text translation", () => {
  const all = Object.entries(fixture as Record<string, string[]>).flatMap(([k, v]) => v.map((s) => [k, s] as const));

  it("covers every string the engines produce (no English left in Arabic mode)", () => {
    const misses = all.map(([k, s]) => [k, s, tr("ar", s)] as const).filter(([, , t]) => leftoverEnglish(t).length > 0);
    expect(misses.map(([k, s, t]) => `${k}: ${s} => ${t}`), "untranslated").toEqual([]);
    expect(all.length).toBeGreaterThan(300);
  });

  it("shows readable English (no raw codes or prefixes) in English mode", () => {
    for (const [k, s] of all) {
      const out = tr("en", s);
      expect(/^(gate|probe|observe):/.test(out), `${k}: ${s} => ${out}`).toBe(false);
      if (["action", "audit_action", "factor", "check", "evidence"].includes(k)) {
        expect(/^[A-Z0-9_]+$/.test(out) || /^[a-z]+(_[a-z]+)+$/.test(out), `raw code left: ${s} => ${out}`).toBe(false);
      }
    }
    expect(tr("en", "Command & Control")).toBe("Command & Control");   // English text stays as written
  });

  it("translates templates with numbers and hosts", () => {
    expect(tr("ar", "Risk 94 / confidence 98% on Tier-1 (auto threshold 90)")).toBe("الخطورة 94 والثقة 98% على Tier-1 (عتبة الاحتواء الآلي 90)");
    expect(tr("ar", "Command & Control")).toBe("اتصال بخادم تحكم (C2)");
    expect(tr("ar", "")).toBe("—");
    expect(trList("ar", ["BLOCK_C2", "ISOLATE_ASSET"])).toBe("حظر خادم التحكم، عزل الأصل");
    expect(trList("en", ["BLOCK_C2"])).toBe("Block C2 server");
  });
});
