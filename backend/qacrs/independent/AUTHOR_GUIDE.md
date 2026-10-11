# دليل كاتب السيناريوهات المستقلة / Independent scenario author guide

اكتب حوادث اختراق **افتراضية** على إحدى الشبكتين أدناه، دون أن ترى أي قرار من Q-ACRS. لكل سيناريو:
الأجهزة المخترقة، وخطورة كل جهاز من 1 إلى 10 (كم خطرًا يبقى لو اكتفينا بتقييده بدل عزله)، ووصف قصير.
Write hypothetical incidents on one of the networks below without seeing any Q-ACRS decision. For each:
hacked machines, a risk 1-10 per machine (risk left if we only restrict it), and a short description.

- استخدم أسماء الأجهزة كما هي حرفيًا. / Use machine names exactly as listed.
- لا تكتب بيانات شخصية. / Do not include personal data.
- يمكنك إضافة رأيك كخبير في حقل `expert_view` (لا يدخل في الحساب). / Optional `expert_view` is not scored.
- ابدأ من الملف `TEMPLATE.json`. / Start from `TEMPLATE.json`.

## net12 (12 machines)

| machine | role | can be isolated | two-person rule |
|---|---|---|---|
| `dc` | domain controller (logins) | yes | yes |
| `files` | file server | yes |  |
| `web1` | appointments website (twin 1) | yes |  |
| `web2` | appointments website (twin 2) | yes |  |
| `app1` | nurse app server (twin 1) | yes |  |
| `app2` | nurse app server (twin 2) | yes |  |
| `db` | patient records database | yes | yes |
| `mri` | MRI console | **never** |  |
| `lab` | lab analyzer | **never** |  |
| `pc_recep` | reception PC | yes |  |
| `pc_nurse` | nurse station PC | yes |  |
| `pc_admin` | admin PC | yes |  |

Services: `logins` runs on dc; `appointments` runs on web1 + web2, needs db; `nurse_app` runs on app1 + app2, needs db

Links (who can open connections to whom): files→dc, web1→app1, web2→app2, app1→db, app2→db, pc_nurse→app1, pc_admin→db, pc_recep→web1, lab→db, pc_admin→dc, pc_nurse→files, pc_recep→files

## net22 (22 machines)

| machine | role | can be isolated | two-person rule |
|---|---|---|---|
| `dc` | domain controller (logins) | yes | yes |
| `files` | file server | yes |  |
| `web1_a` | appointments website (twin 1) | yes |  |
| `web2_a` | appointments website (twin 2) | yes |  |
| `app1_a` | nurse app server (twin 1) | yes |  |
| `app2_a` | nurse app server (twin 2) | yes |  |
| `db_a` | patient records database | yes | yes |
| `mri_a` | MRI console | **never** |  |
| `lab_a` | lab analyzer | **never** |  |
| `pc_recep_a` | reception PC | yes |  |
| `pc_nurse_a` | nurse station PC | yes |  |
| `pc_admin_a` | admin PC | yes |  |
| `web1_b` | appointments website (twin 1) | yes |  |
| `web2_b` | appointments website (twin 2) | yes |  |
| `app1_b` | nurse app server (twin 1) | yes |  |
| `app2_b` | nurse app server (twin 2) | yes |  |
| `db_b` | patient records database | yes | yes |
| `mri_b` | MRI console | **never** |  |
| `lab_b` | lab analyzer | **never** |  |
| `pc_recep_b` | reception PC | yes |  |
| `pc_nurse_b` | nurse station PC | yes |  |
| `pc_admin_b` | admin PC | yes |  |

Services: `logins` runs on dc; `appointments_a` runs on web1_a + web2_a, needs db_a; `nurse_app_a` runs on app1_a + app2_a, needs db_a; `appointments_b` runs on web1_b + web2_b, needs db_b; `nurse_app_b` runs on app1_b + app2_b, needs db_b

Links (who can open connections to whom): files→dc, web1_a→app1_a, web2_a→app2_a, app1_a→db_a, app2_a→db_a, pc_nurse_a→app1_a, pc_admin_a→db_a, pc_recep_a→web1_a, lab_a→db_a, pc_admin_a→dc, pc_nurse_a→files, pc_recep_a→files, web1_b→app1_b, web2_b→app2_b, app1_b→db_b, app2_b→db_b, pc_nurse_b→app1_b, pc_admin_b→db_b, pc_recep_b→web1_b, lab_b→db_b, pc_admin_b→dc, pc_nurse_b→files, pc_recep_b→files
