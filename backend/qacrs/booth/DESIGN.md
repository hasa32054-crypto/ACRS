# Booth design record (v12, 2026-10-19)

**Direction:** «غرفة عمليات ليلية», a night operations room (chosen by the student on 2026-10-19; it replaces the
light "drafting paper" world). The hospital network is a live engineering instrument:
- packets walk the live links;
- the attack flows along its path;
- a scan passes when ACRS decides;
- then the network rewires: isolated stations detach, segmented ones get a wall drawn round them, cut links go dark,
  and clinical links stay lit;
- the decision pipeline lights up step by step (alert, fixed rules, optimiser, safety gate, ML-DSA signature).

**New first tab, "Real incidents":** 83 documented incidents by sector.
- Normal run, or a fault run: an injected optimiser crash, then kill and restart from disk, then the recovery terminal
  and immunity.
- Every line on screen is produced by the real code.

**Dials:** variance 6 · motion 7 · density 5.

**Tokens:**
- Dark is the default: background #060A0D, surfaces #0D161C and #132029.
- Signals: alive #3FD49A, attack #FF5B3F, segment #F3B544, human #72AAFF, isolate #8A9AA4.
- A light theme is available on toggle.
- Type: IBM Plex Sans Arabic, with Plex Mono for data.
- Easing: ease-out cubic-bezier(.23,1,.32,1) and ease-in-out cubic-bezier(.77,0,.175,1).
- UI transitions run 120–320 ms; the scan runs 750 ms and the station rewire 500 ms, staggered by position.
- Reduced motion turns off all movement.

**Kept on purpose (detector advisories):**
- the ECG heartbeat loop is the "services alive" metaphor and stops under reduced motion;
- the QR `<img>` elements stay hidden until the server fills them.

---

## Previous record (v9 booth, light "drafting paper" world)


**Direction (chosen by the student):** «المستشفى الذي يغيّر شكله أثناء الهجوم», the hospital that changes shape during an
attack.
- The network is a living floor plan: each department is a zone, and each device is a station inside it.
- Attack paths are drawn on the plan.
- After a decision, the geometry changes:
  - isolated stations detach and fade;
  - segmented stations get a wall (an amber ring), and only their clinical links stay lit;
  - restricted stations get a "channel cut" badge;
  - held decisions get a "human" badge.
- Healthy services keep beating on the ECG strip.

**Context (layer 0)**
- Audience: SAIF judges and visitors, standing and short on time, many of them security professionals; Ibdaa judges.
- Job: let a visitor attack the hospital, watch ACRS contain it with services alive, and then check the evidence.
- Personality: precise, calm, clinical.
- Platform: an offline web page on a laptop or a large monitor.
- Language: Arabic first, right to left, with an English toggle.

**Dials (layer 2):**
- variance 6: the map dominates, with an asymmetric rail;
- motion 5: the rewiring is the story;
- density 5.

## Tokens (`web/app.css`, `:root`)

**Themes.** Light is "drafting paper": warm off-white (#F3F0E8) with dark ink. Dark is "night shift": blue graphite (#0D1316). Both are explicit, and the toggle is stored per viewer.

**Signals.** Each one also has a shape, so colour is never the only cue:

| Signal | Light | Dark |
|---|---|---|
| Alive | #17805C | #3DBE8E |
| Attack | #C8361B | #FF6A4D |
| Isolate (graphite) | #67737A | #8F9CA1 |
| Segment (amber) | #A86E00 | #F0B441 |
| Human | #2457B8 | #78AEFF |

**Type.**
- IBM Plex Sans Arabic for Arabic and Latin, and IBM Plex Mono for numbers. Both are served locally from `web/fonts` under the OFL licence.
- The scale has a ratio of 1.25 on a 17 px base (19 px at 1600 px and wider).
- Arabic line height is 1.7, with no letter spacing on Arabic.

**Space, radius and shadows.**
- Spacing steps: 4, 8, 12, 16, 24, 32, 48 and 64 px.
- Radius is 4 px on controls and 8 px on panels.
- There are 3 shadow levels.

**Motion.**
- UI transitions run 120–320 ms, ease-out on entry and ease-in on exit.
- Only transform and opacity are animated.
- Buttons press to a scale of 0.97.
- `prefers-reduced-motion` turns off all motion, including the ECG.

## Quality (layer 3)

- **Contrast.** Every text pair is at least AA, computed: ink-3 is 5.2 (light) and 6.1 (dark); attack text is 5.7 and 6.8; text on attack buttons is 5.3 and 6.9.
- **Interaction.**
  - All interactive targets are at least 44 px.
  - Focus rings are visible.
  - Map stations are keyboard operable with Enter or Space, and carry an `aria-label`.
- **States.** Loading, disabled, empty, error, refused (a shake plus a hint) and confirm-to-delete are all handled.
- **Small screens.** There is no horizontal page scroll at 375 px; the map scrolls inside its own frame on phones.
- **CSP.** There is no inline script or style.

The impeccable detector flags 2 things that remain on purpose:
- the ECG loop is the heartbeat metaphor (idea 9), and it stops under reduced motion;
- the QR `<img>` elements are `hidden` until the server fills them.

## Critique (layer 6), scored after fixes

| Axis | Score | Note |
|---|---|---|
| Hierarchy | 8 | One focal point (the map); the decision card status is the second read |
| Typography | 8 | Plex Arabic and Mono; tabular numbers |
| Colour | 8 | Restrained semantic palette; no gradients, glass or neon |
| Spacing | 8 | 4/8 rhythm; the rail and the map align |
| States | 8 | See above |
| Motion | 8 | The rewire explains the change; nothing decorative |
| Accessibility | 8 | AA contrast, keyboard, labels, reduced motion |
| Originality | 8 | A floor plan that rewires itself, not a SOC dashboard |
