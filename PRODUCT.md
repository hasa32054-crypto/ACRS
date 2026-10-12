# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Booth app: static HTML/CSS/JS that works fully offline, served by a Python standard-library server on the
presenter's laptop. It has no CDN or internet dependency, because the user chose "HTML that works without internet".

## Users

- **Primary:** judges and visitors at the booth named «HASSAN» at the SAIF cybersecurity competition (Ministry of
  Interior with Tuwaiq Academy, November 2026). They are standing, have a few minutes, and many are security
  professionals.
- **Also:** Ibdaa / Mawhiba judges reviewing the research project (HASSAN).
- **Presenter:** the student, Hassan Alyanbawi, driving the demo and answering questions.

## Product Purpose

HASSAN, the Hybrid Adaptive Safety-gated System for Attack Neutralization, chooses the minimum effective containment
for a hospital network under attack. It isolates, restricts or segments machines, keeps clinical services running,
never breaks safety rules, and escalates critical decisions to humans. The booth app lets a visitor see this happen
live and test it themselves.

Success means a judge leaves convinced by what they tried with their own hands, not by claims.

## Positioning

- One decision for the whole network, with service replicas modelled.
- A third action, SEGMENT, for critical servers.
- A safety gate that is independent of the solver, with a verifiable certificate.
- Anti-weaponization: forged alerts cannot force an outage.
- A quantum hardware run with a safety gate on top of it.
- Pre-registered science, with failures published.

## Operating Context

- An exhibition booth with noise and short attention spans.
- The screen is undecided: a laptop or a large monitor, so the app must work on both.
- Venue Wi-Fi may be unreliable, so everything runs locally.
- Optional two-laptop mini hospital: a Linux Mint laptop runs the hospital containers and firewall; a Windows laptop
  runs HASSAN and the display.

## Capabilities and Constraints

- Every number shown must come from the result files in `backend/qacrs/results`. Never invent figures.
- Wording about Saudi frameworks is "designed to support", never "certified" or "compliant".
- No quantum-advantage claim.
- The demo never runs real malware. Attacks are scenarios: which machines are compromised, and their risk.
- No free-text attack converter. Visitors build attacks by picking machines on the map.
- HASSAN itself must be hardened. The API needs a token, signed plans, and validated input, and the agent applies only
  allowlisted rules in its own chain. A protection tool must not become a hole in the system it protects.
- Locked files for the blind test must not be modified: `hassan.py`, `hassan_v9.py`, `qubo_v7.py`, `qubo_builder.py`,
  `escalation.py`, `safety_checks.py`, `network.py`, `realism_v8.py`, `hospital_ar.py`, `blind_v9.py`, `stats.py`.

## Brand Commitments

- Name: HASSAN, always written in Latin letters, also inside Arabic text (user decision, 2026-10-12).
- SAIF registration name stays «ACRS: Automated Compromise Response System»; Ibdaa uses HASSAN. The booth shows «ACRS · HASSAN» (HASSAN = the engine of ACRS).
- Language: Arabic first (RTL), with an English toggle.

## Evidence on Hand

The evidence is in these files:
- `docs/qacrs/RESULTS_v7_v8.md`, `RESULTS_v9.md`, `RESULTS_IBM_E7.md`, `RESULTS_IBM_E8.md`, `RESULTS_IBM_E9.md`;
- `SAUDI_ALIGNMENT_AR.md`;
- figures in `docs/qacrs/figures`;
- raw IBM counts in `backend/qacrs/results/v3/ibm`.

There are no testimonials, customers or deployments, and none may be implied.

## Product Principles

1. Let the visitor try it: show, don't claim.
2. Every number is traceable to a file.
3. Honest limits are part of the pitch.
4. Safety first, visibly: the human decides the critical cases.
5. It works offline, every time.

## Accessibility & Inclusion

- Arabic RTL and English LTR.
- Readable from standing distance.
- Color is never the only signal: use icons and labels for up and down states.
- Reduced motion is respected.
