# ACRS — Pre-registration v13 (immunity refinement only)

**Written:** 2026-10-18, after `RESULTS_v12.md` was published and **before any v13 code or result.** Committed alone.

## Why
v12's T9 missed by one incident: on Change Healthcare the immunity first-hop rule isolated the Citrix portal at hop 1,
and the portal is itself the only replica of the "remote access" service, so immunisation *cost* a service (3 → 4).
The rule was "isolate the matched first-hop host whatever its risk". That is too blunt when the host carries a service.

## The one change (D13-v13)
`first_hop_actions` becomes: a host matching a known first hop is **isolated at once only if isolating it takes no
service down that is currently up**; otherwise it is **not** isolated by immunity — its outgoing path links are
already shielded permanently (the lateral protocol on them is blocked), and the ordinary v12 floor, solver and locked
gate decide the rest exactly as without immunity. Nothing else changes: no weight, no threshold, no other rule.

## Targets (same as v12 T9, re-stated)
| ID | Target | Set |
|---|---|---|
| T9-v13 | same attack: contained with ≤ services down than before immunisation in **8/8**; similar attack ≤ before in ≥ 6/8; dissimilar attack: decision identical to the un-immunised engine in all cases where a dissimilar variant exists | the 8 real incidents, same generators and seeds as v12 (12015) |
| T9b-v13 | on the open corpus (75 cases): same-attack replay after immunisation never takes **more** services down than before, in 100 % of cases | corpus |

If T9-v13 fails, immunity stays off by default and the failure is published. The v12 result (7/8) stays in
`RESULTS_v12.md` unchanged.

### ملخص عربي
تغيير واحد فقط: المناعة تعزل الجهاز المطابق لأول قفزة **إلا إذا كان عزله يسقط خدمة شغّالة**؛ عندها تكتفي بالدروع الدائمة
على روابطه وتترك القرار للمحرك العادي. الأهداف نفسها، ويُضاف اختبار على الكوربس كله (75 حالة): المناعة لا تزيد الخدمات
المتوقفة أبدًا. إن فشل، تبقى المناعة مطفأة ويُنشر الفشل.
