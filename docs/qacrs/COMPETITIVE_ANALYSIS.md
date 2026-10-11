# HASSAN compared with existing response systems (feature P1)

> Research notes collected with an AI tool (Claude) on 2026-10-11. Every row cites the page that was opened and read
> on that date. **ISEF rule:** open each link yourself, check the claim, and write any citation in your own words.
> Vendor pages describe products as the vendor sees them; they are claims, not independent evaluations.

## What each system does when an attack is found

| System | Containment action | Who decides | How critical assets are treated | Source |
|---|---|---|---|---|
| **SOAR playbooks** (generic) | runs a fixed playbook per alert type (e.g. isolate host, block IP) | the playbook author, ahead of time | whatever the playbook says; the playbook sees one alert, not the network | Islam, Babar, Nepal, *A Multi-Vocal Review of Security Orchestration*, [arXiv:2002.09190](https://arxiv.org/abs/2002.09190) |
| **Microsoft Defender XDR – automatic attack disruption** | contain device (block its communication on all onboarded devices), contain user, disable user, revoke sessions | automatic at high confidence (vendor states ≥ 99 % detector precision); humans review and can undo afterwards | a manual **exclusion list** of users, devices and IPs that are never contained automatically | [Microsoft Learn: automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption) |
| **CrowdStrike Falcon – network containment** | host loses all network connections except to the CrowdStrike cloud and an allow-listed set of internal IPs | the documented flow is an analyst clicking “Network Contain this machine”; lifting is also manual | per-host allowlist of internal IPs; no model of services or replicas in the documented flow | [CrowdStrike tech center: network contain an endpoint](https://www.crowdstrike.com/blog/tech-center/network-contain-endpoint-falcon/) · automation through the API: [CrowdStrike developer: automate response](https://developer.crowdstrike.com/accomplish/automate-response/) |
| **Darktrace autonomous response (Antigena)** | graded: block one connection → enforce the device’s normal “pattern of life” → block all outbound; ransomware block quarantines the device | **Human Confirmation Mode** (team approves each action) or Active Mode (automatic) | not described in the source read | [Darktrace blog: stop the clock](https://www.darktrace.com/ja/blog/stop-the-clock-how-autonomous-response-contains-cyber-threats-in-seconds) |
| **Illumio segmentation** | pre-built segmentation policy that limits lateral movement to high-value assets | policy authors, ahead of time | the page read describes asset/traffic maps and claims ransomware is stopped “in minutes”, without describing an automatic response | [Illumio: critical asset protection](https://www.illumio.com/solutions/critical-asset-protection) |
| **Academic IRS – multi-objective** | picks countermeasures by optimising security benefit vs service impact vs cost on a service-dependency graph | automatic | no hard safety constraints and no independent check after the optimiser | Shameli-Sendi et al. (2018), IEEE TDSC 15(5):755–770, DOI 10.1109/TDSC.2016.2615622 |
| **Academic IRS – game theory** | security-vs-QoS stable matching | automatic; weights set by the administrator | no hard safety constraints, no human-approval path, simulation only | Bozorgchenani et al. (2023), [arXiv:2303.08544](https://arxiv.org/abs/2303.08544) |

## Where HASSAN is different, and where it is not

| Point | Existing systems (as documented above) | HASSAN (evidence in this repo) |
|---|---|---|
| Unit of decision | one host, one user or one alert at a time | one decision for the whole network, as a QUBO with twin/replica coupling (`qubo_v7.py`) |
| Critical servers | either never touched (exclusion list) or fully contained | a third option, **SEGMENT**: cut the server’s C2 channel and inbound traffic from compromised machines automatically, so the service stays up; full isolation still needs two-person approval (v7: 253/259 chains contained automatically, 0 services down; `RESULTS_v7_v8.md`) |
| Guarantee that the optimiser cannot break a safety rule | not documented | penalty dominance proven and unit-tested; independent checker after any solver; proof-carrying certificate re-verified in 20,000 random forged sets with 0 violations |
| Can a forged alert turn the defence against the hospital? | not documented | exhaustive forged sets of 1–3 machines: worst services forced down = 0 (safe full isolation: 1); rate limit 3 isolations/min |
| Explanation | incident banners / tags | bilingual decision card with a counterfactual for every decision (1956/1956) |
| Human approval | Darktrace offers a mode where *every* action waits; Defender acts first, humans undo | only the risky part waits (critical isolation, twin dilemma, never-isolatable source); the rest is automatic |
| Maturity | products in production use | **research prototype**: synthetic networks, loopback sandbox, design-assumption weights; never run on a real hospital network |
| Detection | products include detection | HASSAN assumes alerts are given; it only decides the response |

### What we must not claim
- Not “better than Defender/CrowdStrike/Darktrace”: we did not run them, and they solve detection too.
- Darktrace’s Human Confirmation Mode and Defender’s exclusion list are real answers to the same worry; HASSAN’s
  contribution is a finer-grained middle path (SEGMENT + gates) with a checkable certificate, measured on synthetic data.

### ملخص عربي
الأنظمة التجارية إما تعزل الجهاز كاملًا أو تستثنيه بقائمة يدوية، وقرارها لكل جهاز وحده. HASSAN يقرر للشبكة كلها،
ويضيف خيارًا ثالثًا للخوادم الحرجة (التجزئة)، ويرفق شهادة يمكن التحقق منها. لكنه نموذج بحثي على شبكات اصطناعية، ولم
نشغّل الأنظمة التجارية بأنفسنا، فلا ندّعي التفوق عليها.
