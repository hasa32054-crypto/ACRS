# Conversion brief (v11, ACRS). Convert REAL cyber incidents into a small network + alert set from PUBLIC sources only.

Research each incident with web search / fetch (CISA advisories, NAO, NCSC, PwC HSE review, congressional testimony,
vendor incident reports, BSI/press). Prefer primary/official sources. For each incident you MUST find: the entry point,
at least one lateral hop, what was disrupted, and the moment defenders first detected it. If you cannot find an entry
point AND one lateral hop in a public source, set "dropped": true with the reason.

## Mechanical rules (do not invent beyond them)
1. Machines: every host/server/system named or clearly implied in the report = one machine. Generic groups
   ("hundreds of workstations") = at most 10 machines of that type (use 3-10). Role copied from the report.
   Naming: workstations/laptops -> "pc_<x>"; internet-facing entry (VPN appliance, Citrix, web server, RDP host,
   email gateway) -> "web_<x>"; internal servers -> "srv_<x>"; domain controller -> "dc"; file server -> "files";
   medical/industrial devices -> "dev_<x>". Lowercase, ascii, underscores.
2. isolatable=false ONLY if the report says disconnecting it endangers life or physical safety (medical devices in
   use, safety-instrumented / OT controllers). critical=true if the report says its loss stops a core service
   (DC, core banking DB, LIMS, billing/claims, SWIFT Alliance server, ERP). Else plain.
3. disruption (1-5): life-critical 5, core business 3-4, support 2, workstation 1.
4. Services: every business service the report says was disrupted or at risk = one service, value:
   life-critical 30, core business 20-25, support 10. replicas = machines that run it (2 only if the report says
   there was redundancy, else 1). depends_on = machines it needs (DB, DC) if the report says so.
5. Links [from, to]: one per lateral movement the report describes (A -> B). Plus every workstation -> dc and
   workstation -> files if the report mentions domain credentials being used. No other links.
6. Detection moments: the machines the report says were compromised AT THE MOMENT defenders first detected
   (or first public knowledge if not stated). Later encryption of everything is NOT the alert set. If the report
   gives several detection moments (e.g. first alert ignored, later real detection), give each as a separate moment.
7. Leftover risk per hacked machine from the ATT&CK technique the report attributes to it:
   ransomware/wiper deployed on host (T1486/T1485)=9; domain-admin cred theft / Kerberoast (T1003/T1558)=8;
   active C2 beacon (T1071/T1219)=7; lateral tool present (T1021, PsExec, AnyDesk, Cobalt Strike moving)=6;
   initial access only, no confirmed post-exploitation (T1190/T1566/T1133)=5. Several apply -> highest.
8. If the report does not say, leave the plain default and log it in "ambiguities". Never guess.
   Max ~25 machines per incident (the engine is exact up to ~20 binary variables, otherwise annealing).

## Output: ONE JSON file per incident at the path given, exactly this schema (no comments):
{
 "incident": "...", "year": 2017, "sector": "health",
 "sources": [{"title":"...","url":"...","what_it_gave":"entry point / hops / detection"}],
 "narrative_before": "3-6 sentences: what actually happened, timeline, impact (with the figures from sources, cited)",
 "machines": [{"name":"pc_x","role":"...","isolatable":true,"critical":false,"disruption":1}],
 "services": [{"name":"...","value":20,"replicas":["srv_x"],"depends_on":["dc"]}],
 "links": [["pc_x","dc"]],
 "detection_moments": [{"id":"m1","hacked":{"pc_x":7},"description":"...","evidence":"quote or close paraphrase + source title"}],
 "attack_path": [["web_vpn","srv_x","hop description + technique id"]],
 "ambiguities": ["..."],
 "dropped": false, "drop_reason": ""
}
Then ALSO return the full JSON text in your final message. Be rigorous: every number and every hop must be traceable
to a cited source. Do not pad. Do not flatter.

## Corpus addendum (v12 stage 1-b)
- Same schema, same rules. One JSON per case. Filename: <source>_<year>_<slug>.json (lowercase).
- Add "techniques" per hacked host inside each detection moment: "techniques": {"pc_x": ["T1566.001","T1059.001"]}.
  Risk per host is then the HIGHEST of: T1486/T1485/T1561/T1490=9; T1003/T1558=8; T1071/T1219/T1105/T1572=7;
  T1021/T1047/T1570/T1210=6; T1190/T1566/T1133/T1078/T1189/T1204/T1195=5. Put that number in "hacked".
- Service values ONLY from {30 life-critical/emergency, 25 national or >10k affected, 20 core business, 10 support}.
- Many write-ups name hosts by role only (e.g. "the file server", "a domain controller", "the beachhead workstation").
  That is enough: one machine per named role. Do NOT invent hosts the write-up does not mention.
- Detection moments: the write-up's own timeline markers (initial access, first lateral, domain admin, exfil, encryption).
  Use up to 4 per case. The alert set at a moment = hosts the write-up says were compromised by then.
- If the write-up gives no entry host or no hop → dropped=true with reason. Dropped files are still written.
