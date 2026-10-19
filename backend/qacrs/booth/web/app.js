/* ACRS booth UI. No framework, no network beyond this laptop's own server. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const SVGNS = "http://www.w3.org/2000/svg";
  const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const store = {
    get(k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* private mode: fine */ } },
  };

  // ------------------------------------------------------------------------------------------- state
  const S = {
    lang: store.get("hassan-lang") === "en" ? "en" : "ar",
    token: null, model: null, M: {}, adj: {}, zoneOf: {},
    mode: "real", risk: 8, picks: [], last: null, view: "break",
    maps: {}, quantum: null, judge: null, ransom: null, attacks: [], real: { mode: "normal", token: 0 },
  };
  const t = (k, vars) => {
    let s = (I18N[S.lang] && I18N[S.lang][k]) ?? I18N.ar[k] ?? k;
    if (vars && typeof s === "string") for (const [a, b] of Object.entries(vars)) s = s.split("{" + a + "}").join(b);
    return s;
  };
  const nf = (x, d = 0) => new Intl.NumberFormat(S.lang === "ar" ? "ar-SA-u-nu-latn" : "en-US",
    { minimumFractionDigits: d, maximumFractionDigits: d }).format(x);
  const pct = (x, d = 1) => nf(100 * x, d) + "%";

  // ------------------------------------------------------------------------------------------- api
  class ApiError extends Error {}
  async function api(path, body) {
    const opt = body === undefined ? {} : {
      method: "POST", body: JSON.stringify(body),
      headers: { "Content-Type": "application/json", "X-HASSAN-Token": S.token || "" },
    };
    let res;
    try { res = await fetch(path, opt); } catch (e) { throw new ApiError(t("err.net")); }
    let data = {};
    try { data = await res.json(); } catch (e) { /* empty */ }
    if (!res.ok) throw new ApiError(t("err.api", { e: data.error || res.status }));
    return data;
  }
  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg; el.classList.add("is-on");
    clearTimeout(toast._t); toast._t = setTimeout(() => el.classList.remove("is-on"), 2600);
  }
  function busy(btn, on) { btn.classList.toggle("is-loading", on); btn.setAttribute("aria-busy", on ? "true" : "false"); }
  function el(tag, attrs = {}, kids = []) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") n.className = v; else if (k === "text") n.textContent = v; else n.setAttribute(k, v);
    }
    for (const c of [].concat(kids)) if (c != null) n.append(c);
    return n;
  }
  function sv(tag, attrs = {}) {
    const n = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  }
  const svgData = (svg) => "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
  const setImg = (sel, svg, alt) => { const i = $(sel); i.src = svgData(svg); i.alt = alt; i.hidden = false; };
  const PC_EN = { nurse: "Nurse PC", doc: "Doctor PC", admin: "Admin PC", recep: "Reception PC" };
  const mname = (id) => {
    if (!S.M[id]) return id;
    if (S.lang === "ar") return S.M[id].ar;
    const m = /^pc_([a-z]+)(\d+)$/.exec(id);
    return m ? `${PC_EN[m[1]] || "PC"} ${m[2]}` : S.M[id].en;
  };
  const sname = (id) => { const s = S.model.services.find((x) => x.id === id); return s ? (S.lang === "ar" ? s.ar : s.id) : id; };

  // ------------------------------------------------------------------------------------------- map geometry
  const ZONE_BOX = {
    front: [16, 16, 330, 200], nursing: [362, 16, 300, 200], doctors: [678, 16, 300, 200], admin: [994, 16, 190, 200],
    identity: [16, 232, 330, 250], records: [362, 232, 440, 250], er: [818, 232, 366, 250],
    infra: [16, 498, 330, 256], imaging: [362, 498, 440, 256], lab: [818, 498, 366, 256],
  };
  const SHORT = {
    dc1: ["دخول 1", "Login 1"], dc2: ["دخول 2", "Login 2"], vpn: ["VPN", "VPN"], wifi: ["لاسلكي", "Wi-Fi"], badge: ["بطاقات", "Badges"],
    ehr_db: ["قاعدة السجلات", "EHR DB"], ehr_app1: ["سجلات 1", "EHR 1"], ehr_app2: ["سجلات 2", "EHR 2"], hl7_1: ["ربط 1", "HL7 1"], hl7_2: ["ربط 2", "HL7 2"],
    er1: ["طوارئ 1", "ER 1"], er2: ["طوارئ 2", "ER 2"], monitor_gw: ["مراقبة المرضى", "Monitors"], pump_gw: ["مضخات", "Pumps"], nursecall: ["نداء التمريض", "Nurse call"],
    pacs_store: ["أرشيف الأشعة", "PACS store"], pacs1: ["أشعة 1", "PACS 1"], pacs2: ["أشعة 2", "PACS 2"], ct: ["مقطعية", "CT"], mri: ["رنين", "MRI"], xray: ["سينية", "X-ray"],
    lis: ["نظام المختبر", "LIS"], lab_a1: ["محلل 1", "Analyzer 1"], lab_a2: ["محلل 2", "Analyzer 2"], lab_a3: ["محلل 3", "Analyzer 3"], pharm: ["الصيدلية", "Pharmacy"],
    files: ["ملفات", "Files"], backup: ["نسخ احتياطي", "Backup"], email: ["بريد", "Email"], print: ["طابعات", "Print"], hvac: ["تحكم المبنى", "HVAC"],
    web1: ["بوابة 1", "Portal 1"], web2: ["بوابة 2", "Portal 2"],
  };
  const shortLabel = (id) => SHORT[id] ? SHORT[id][S.lang === "ar" ? 0 : 1] : id.replace(/^pc_[a-z]+/, "");
  const kindOf = (m) => m.critical ? "critical" : !m.isolatable ? "medical" : m.id.startsWith("pc_") ? "workstation" : "server";

  function layout() {
    const pos = {};
    for (const z of S.model.zones) {
      const [x, y, w, h] = ZONE_BOX[z.id];
      const n = z.machines.length, top = 52, ih = h - top - 18;
      let rows = Math.max(1, Math.round(Math.sqrt(n * ih / w)));
      if (n <= 5 && w > 300) rows = Math.min(rows, 2);
      const cols = Math.ceil(n / rows);
      z.machines.forEach((id, i) => {
        const r = Math.floor(i / cols), c = i % cols;
        const inRow = Math.min(cols, n - r * cols);
        const cw = w / inRow;
        pos[id] = { x: x + cw * (c + 0.5), y: y + top + (ih / rows) * (r + 0.5), cx: x + w / 2, cy: y + h / 2 };
      });
    }
    return pos;
  }

  /* links are gentle quadratic curves (deterministic bend), so dense meshes read as flows, not a hairball */
  function curve(a, b) {
    const pa = S.pos[a], pb = S.pos[b];
    const mx = (pa.x + pb.x) / 2, my = (pa.y + pb.y) / 2, dx = pb.x - pa.x, dy = pb.y - pa.y, len = Math.hypot(dx, dy) || 1;
    let h = 0; for (const ch of a + b) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    const k = (h % 2 ? 1 : -1) * Math.min(60, len * 0.14);
    const cx = mx - (dy / len) * k, cy = my + (dx / len) * k;
    return {
      d: `M${pa.x.toFixed(1)},${pa.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${pb.x.toFixed(1)},${pb.y.toFixed(1)}`,
      at: (t) => { const u = 1 - t; return [u * u * pa.x + 2 * u * t * cx + t * t * pb.x, u * u * pa.y + 2 * u * t * cy + t * t * pb.y]; },
    };
  }

  function buildMap(svg, { interactive = false, onPick = null, packets = false } = {}) {
    svg.textContent = "";
    const pos = S.pos;
    const gZones = sv("g"), gLinks = sv("g"), gHops = sv("g"), gPk = sv("g"), gSt = sv("g");
    svg.append(gZones, gLinks, gHops, gPk, gSt);
    const zones = {};
    for (const z of S.model.zones) {
      const [x, y, w, h] = ZONE_BOX[z.id];
      const g = sv("g", { class: "zone" });
      g.append(sv("rect", { x, y, width: w, height: h, rx: 8 }));
      g.append(sv("path", { class: "tick", d: `M${x + 1},${y + 16}V${y + 1}H${x + 16}M${x + w - 16},${y + h - 1}H${x + w - 1}V${y + h - 16}` }));
      const title = sv("text", { x: S.lang === "ar" ? x + w - 14 : x + 14, y: y + 26, "text-anchor": S.lang === "ar" ? "end" : "start" });
      title.textContent = S.lang === "ar" ? z.ar : z.en;
      g.append(title);
      if (S.lang === "ar") {
        const en = sv("text", { x: x + 14, y: y + 26, class: "zone-en" }); en.textContent = z.en.toUpperCase(); g.append(en);
      }
      gZones.append(g); zones[z.id] = g;
    }
    const links = S.model.links.map(([a, b]) => {
      const cv = curve(a, b);
      const l = sv("path", { d: cv.d, class: "link" });
      gLinks.append(l); return { a, b, el: l, at: cv.at };
    });
    const st = {};
    for (const m of S.model.machines) {
      const p = pos[m.id], kind = kindOf(m);
      const g = sv("g", { class: `st kind-${kind}`, transform: `translate(${p.x},${p.y})`, "data-id": m.id });
      const mv = sv("g", { class: "st-move" });
      mv.append(sv("circle", { class: "pulse", r: 18 }), sv("circle", { class: "ring", r: 23 }), sv("circle", { class: "wall", r: 25 }));
      if (kind === "medical") {
        mv.append(sv("circle", { class: "body", r: 14 }), sv("path", { class: "glyph", d: "M-6,0H6M0,-6V6" }));
      } else if (kind === "workstation") {
        mv.append(sv("rect", { class: "body", x: -13, y: -10, width: 26, height: 18, rx: 2 }), sv("path", { class: "glyph", d: "M-5,13H5" }));
      } else if (kind === "critical") {
        mv.append(sv("rect", { class: "body", x: -16, y: -16, width: 32, height: 32, rx: 3 }), sv("path", { class: "glyph", d: "M-8,-6H8M-8,0H8M-8,6H8" }));
      } else {
        mv.append(sv("rect", { class: "body", x: -13, y: -13, width: 26, height: 26, rx: 3 }), sv("path", { class: "glyph", d: "M-6,-4H6M-6,4H6" }));
      }
      const lab = sv("text", { class: "label", y: kind === "critical" ? 34 : 31 }); lab.textContent = shortLabel(m.id); mv.append(lab);
      const cut = sv("g", { class: "cut", transform: "translate(15,-15)" });
      cut.append(sv("circle", { r: 7 }), sv("path", { d: "M-3.5,-3.5L3.5,3.5" })); mv.append(cut);
      const hu = sv("g", { class: "human", transform: "translate(-15,-15)" });
      hu.append(sv("circle", { class: "bg", r: 8 }), sv("circle", { class: "h", cy: -2.5, r: 2.4 }), sv("path", { d: "M-4.5,5a4.5,4 0 0 1 9,0z" }));
      mv.append(hu);
      g.append(mv);
      const title = sv("title"); title.textContent = mname(m.id); g.append(title);
      if (interactive) {
        g.setAttribute("tabindex", "0"); g.setAttribute("role", "button");
        g.setAttribute("aria-label", mname(m.id));
        g.addEventListener("click", () => onPick(m.id));
        g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onPick(m.id); } });
      }
      g.addEventListener("pointerenter", () => { for (const l of links) if (l.a === m.id || l.b === m.id) l.el.classList.add("is-hover"); });
      g.addEventListener("pointerleave", () => { for (const l of links) l.el.classList.remove("is-hover"); });
      gSt.append(g); st[m.id] = { g, mv, p };
    }
    const c = { svg, zones, links, st, gHops, gPk, hopKey: "" };
    if (packets) c.packets = true;
    return c;
  }

  /* ambient traffic: packets walk the live links; cut or walled links carry nothing, attack hops carry red */
  const PK = { list: [], raf: 0, last: 0 };
  function packetsStart() {
    const c = S.maps.main; if (!c || reduced()) return;
    c.gPk.textContent = ""; PK.list = [];
    for (let i = 0; i < 26; i++) {
      const l = c.links[(i * 37) % c.links.length];
      const dot = sv("circle", { class: "pkt", r: 2.4 }); c.gPk.append(dot);
      PK.list.push({ l, t: (i * 0.137) % 1, dir: i % 2 ? 1 : -1, v: 0.18 + (i % 5) * 0.04, dot });
    }
    cancelAnimationFrame(PK.raf); PK.last = performance.now(); PK.raf = requestAnimationFrame(packetsTick);
  }
  const linkLive = (l) => !(l.el.classList.contains("is-cut") || l.el.classList.contains("is-walled"));
  function packetsTick(now) {
    PK.raf = requestAnimationFrame(packetsTick);
    const dt = Math.min(0.05, (now - PK.last) / 1000); PK.last = now;
    if (document.hidden || S.view !== "break") return;
    const c = S.maps.main, hops = S.hopSet || new Set();
    for (const p of PK.list) {
      p.t += p.dir * p.v * dt;
      if (p.t > 1 || p.t < 0) {
        const at = p.dir > 0 ? p.l.b : p.l.a;
        const next = c.links.filter((l) => (l.a === at || l.b === at) && l !== p.l && linkLive(l));
        const pool = next.length ? next : c.links.filter(linkLive);
        p.l = pool[Math.floor(Math.random() * pool.length)] || p.l;
        p.dir = p.l.a === at ? 1 : p.l.b === at ? -1 : (Math.random() < .5 ? 1 : -1);
        p.t = p.dir > 0 ? 0 : 1;
      }
      const live = linkLive(p.l);
      const [x, y] = p.l.at(Math.max(0, Math.min(1, p.t)));
      p.dot.setAttribute("cx", x.toFixed(1)); p.dot.setAttribute("cy", y.toFixed(1));
      const atk = hops.has(p.l.a + "|" + p.l.b);
      p.dot.setAttribute("class", "pkt" + (atk ? " is-attack" : p.l.el.classList.contains("is-clinical") ? " is-clinical" : ""));
      p.dot.style.opacity = live ? "" : "0";
    }
  }

  function resetMap(c) {
    for (const { g, mv } of Object.values(c.st)) {
      g.setAttribute("class", g.getAttribute("class").split(" ").filter((x) => x === "st" || x.startsWith("kind-")).join(" "));
      mv.style.transform = ""; mv.style.transitionDelay = "";
      const o = g.querySelector(".order"); if (o) o.remove();
    }
    for (const l of c.links) l.el.setAttribute("class", "link");
    for (const z of Object.values(c.zones)) z.classList.remove("is-hot");
    c.gHops.textContent = "";
  }
  const cls = (c, id, name, on = true) => c.st[id] && c.st[id].g.classList.toggle(name, on);

  function drawHops(c, genuine, stopped = new Set()) {
    c.gHops.textContent = "";
    const set = new Set(genuine), keys = [];
    const prev = new Set((c.hopKey || "").split(";"));
    for (const { a, b } of c.links) {
      if (set.has(a) && set.has(b)) {
        const k = a + "|" + b; keys.push(k);
        const fresh = !prev.has(k) && !reduced();
        c.gHops.append(sv("path", { d: curve(a, b).d, class: "hop" + (stopped.has(a) || stopped.has(b) ? " is-stopped" : fresh ? " is-draw" : "") }));
      }
    }
    c.hopKey = keys.join(";");
    if (c === S.maps.main) S.hopSet = new Set(keys.filter((k) => { const [a, b] = k.split("|"); return !stopped.has(a) && !stopped.has(b); }));
  }

  function clinicalLink(a, b, seg) {
    return S.model.services.some((s) => (seg.has(b) && s.depends_on.includes(b) && s.replicas.includes(a)) ||
                                        (seg.has(a) && s.depends_on.includes(a) && s.replicas.includes(b)));
  }

  /* the rewiring: isolated stations detach, segmented ones get a wall, cut links fade, clinical links stay lit */
  function applyDecision(c, hacked, forged, side) {
    resetMap(c);
    const iso = new Set(side.isolate), seg = new Set(side.segment), res = new Set(side.restrict || []),
      held = new Set(side.held || []), fg = new Set(forged);
    for (const id of Object.keys(hacked)) {
      cls(c, id, fg.has(id) ? "is-forged" : "is-hacked");
      c.zones[S.zoneOf[id]].classList.add("is-hot");
    }
    const stagger = (id) => { if (c.stagger) c.st[id].mv.style.transitionDelay = Math.round((S.pos[id].x / 1200) * 380) + "ms"; };
    for (const id of iso) {
      cls(c, id, "is-isolated"); stagger(id);
      const p = S.pos[id]; let dx = p.x - p.cx, dy = p.y - p.cy; const n = Math.hypot(dx, dy) || 1;
      if (n < 1) { dx = 0; dy = -1; }
      c.st[id].mv.style.transform = `translate(${(dx / n) * 18}px, ${(dy / n) * 18}px)`;
    }
    for (const id of seg) cls(c, id, "is-segmented");
    for (const id of res) cls(c, id, "is-restricted");
    for (const id of held) cls(c, id, "is-held");
    for (const l of c.links) {
      if (iso.has(l.a) || iso.has(l.b)) l.el.classList.add("is-cut");
      else if (seg.has(l.a) || seg.has(l.b)) l.el.classList.add(clinicalLink(l.a, l.b, seg) ? "is-clinical" : "is-walled");
    }
    const genuine = Object.keys(hacked).filter((x) => !fg.has(x));
    drawHops(c, genuine, new Set([...iso, ...seg]));
  }

  // ------------------------------------------------------------------------------------------- ECG (idea 9)
  const BEAT = "M0,20 L22,20 L26,13 L30,27 L35,4 L40,31 L44,20 L96,20";
  function buildEcg(box) {
    box.textContent = "";
    const rows = {};
    for (const s of S.model.services) {
      const row = el("div", { class: "ecg-row" });
      const name = el("div", { class: "ecg-name" }, [el("span", { text: S.lang === "ar" ? s.ar : s.id }), el("span", { class: "ecg-state", text: t("svc.up") })]);
      const tr = el("div", { class: "ecg-trace", "aria-hidden": "true" });
      const svg = sv("svg", { viewBox: "0 0 192 34", preserveAspectRatio: "none" });
      const beat = sv("path", { class: "beat", d: BEAT + " " + BEAT.replace(/(-?\d+),/g, (m, x) => (+x + 96) + ",").replace(/^M/, "L") });
      const flat = sv("path", { class: "flat", d: "M0,20 L192,20" });
      svg.append(beat, flat); tr.append(svg); row.append(name, tr); box.append(row);
      beat.style.animationDuration = (1.3 + (s.value % 7) / 15) + "s";
      rows[s.id] = row;
    }
    return rows;
  }
  function setEcg(rows, down) {
    const d = new Set(down);
    for (const [id, row] of Object.entries(rows)) {
      row.classList.toggle("is-down", d.has(id));
      row.querySelector(".ecg-state").textContent = d.has(id) ? t("svc.down") : t("svc.up");
    }
  }

  // ------------------------------------------------------------------------------------------- legend
  function legend() {
    const box = $("#legend"); box.textContent = "";
    const item = (svgInner, key) => {
      const s = sv("svg", { class: "lg", viewBox: "-12 -12 24 24", "aria-hidden": "true" });
      s.innerHTML = svgInner; // static markup authored here, no user data
      box.append(el("span", {}, [s, el("span", { text: t(key) })]));
    };
    item('<rect x="-8" y="-8" width="16" height="16" rx="2" class="f-attack"/>', "lg.hacked");
    item('<rect x="-8" y="-8" width="16" height="16" rx="2" class="f-attack-soft s-attack dash"/>', "lg.forged");
    item('<rect x="-8" y="-8" width="16" height="16" rx="2" class="f-iso-soft s-iso dash"/>', "lg.isolated");
    item('<circle r="9" class="f-none s-seg w3"/><rect x="-5" y="-5" width="10" height="10" class="f-surface s-ink2"/>', "lg.segmented");
    item('<circle r="7" class="f-surface s-attack"/><path d="M-3.5,-3.5L3.5,3.5" class="s-attack w2"/>', "lg.restricted");
    item('<circle r="8" class="f-human"/><circle cy="-2.5" r="2.4" class="f-white"/><path d="M-4.5,5a4.5,4 0 0 1 9,0z" class="f-white"/>', "lg.held");
    item('<circle r="8" class="f-surface s-alive"/><path d="M-4,0H4M0,-4V4" class="s-alive w2"/>', "lg.medical");
    item('<rect x="-9" y="-9" width="18" height="18" rx="2" class="f-surface s-ink2 w3"/>', "lg.critical");
  }


  // ------------------------------------------------------------------------------------------- 0. real incidents
  const GROUP_ICON = {
    health: "M12 4v16M4 12h16", finance: "M4 20h16M6 20V10M10 20V10M14 20V10M18 20V10M3 10l9-6 9 6",
    industry: "M3 20V9l6 4V9l6 4V5h6v15z", government: "M3 20h18M5 20V11M19 20V11M9 20v-9M15 20v-9M2 11l10-7 10 7z",
    tech: "M4 5h16v11H4zM9 20h6M12 16v4", business: "M5 8h14l-1 12H6zM9 8V6a3 3 0 0 1 6 0v2", other: "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
  };
  const icon = (d) => { const s = sv("svg", { viewBox: "0 0 24 24", "aria-hidden": "true" }); s.append(sv("path", { d })); return s; };
  async function realLoad() {
    if (S.real && S.real.cat) return;
    S.real = { ...S.real, cat: null, group: null, id: null, run: null };
    try { S.real.cat = await api("/api/incidents"); } catch (e) { toast(e.message); return; }
    S.real.group = S.real.cat.groups[0].id;
    renderSectors(); renderIncList();
  }
  function renderSectors() {
    const box = $("#sectors"); box.textContent = "";
    for (const g of S.real.cat.groups) {
      const b = el("button", { class: "sector", "aria-pressed": String(g.id === S.real.group) }, [icon(GROUP_ICON[g.id] || GROUP_ICON.other),
        el("span", { text: S.lang === "ar" ? g.ar : g.en }), el("span", { class: "n", text: String(g.n) })]);
      b.addEventListener("click", () => { S.real.group = g.id; renderSectors(); renderIncList(); });
      box.append(b);
    }
  }
  function renderIncList() {
    const box = $("#incList"); box.textContent = "";
    for (const it of S.real.cat.incidents.filter((x) => x.group === S.real.group)) {
      const b = el("button", { class: "inc", "aria-pressed": String(it.id === S.real.id) }, [
        el("span", { class: "inc-t", text: it.title }),
        el("span", { class: "inc-m" }, [el("span", { class: it.origin === "real" ? "real" : "", text: String(it.year || "") }),
          el("span", { text: `${it.machines} hosts · ${it.moments} alerts` })])]);
      b.addEventListener("click", () => selectIncident(it.id));
      box.append(b);
    }
  }
  function selectIncident(id) {
    const R = S.real; R.id = id; R.token++;
    const it = R.cat.incidents.find((x) => x.id === id);
    renderIncList();
    $("#incTitle").textContent = it.title;
    const meta = $("#incMeta"); meta.textContent = `${it.year || ""} · ${it.sector} · ${it.machines} hosts · ${it.moments} detection moments · `;
    if (it.url) { const a = el("a", { href: it.url, target: "_blank", rel: "noopener noreferrer", text: it.source || "source" }); meta.append(a); }
    $("#runBtn").disabled = false;
    $("#moments").textContent = ""; $("#incMap").textContent = ""; $("#term").hidden = true; $("#incSummary").hidden = true;
    $("#incCard").textContent = "";
    $("#incCard").append(el("div", { class: "empty" }, [el("h2", { text: t("real.ready") }), el("p", { class: "small", text: t("real.ready2") })]));
  }

  // layered layout: the attack path reads left to right, every other host by its distance from the entry
  function incLayout(model) {
    const W = 1000, H = 460, ids = model.machines.map((m) => m.id), adj = {};
    for (const [a, b] of model.links) { (adj[a] ||= []).push(b); (adj[b] ||= []).push(a); }
    const start = (model.path && model.path[0]) || ids[0];
    const layer = { [start]: 0 }, q = [start];
    while (q.length) { const x = q.shift(); for (const y of adj[x] || []) if (!(y in layer)) { layer[y] = layer[x] + 1; q.push(y); } }
    let mx = Math.max(0, ...Object.values(layer));
    for (const id of ids) if (!(id in layer)) layer[id] = ++mx;
    const cols = {}; for (const id of ids) (cols[layer[id]] ||= []).push(id);
    // a crowded layer is split into sub-columns of at most 5, so labels never collide
    const keys = Object.keys(cols).map(Number).sort((a, b) => a - b), slots = [];
    for (const k of keys) { const col = cols[k]; for (let i = 0; i < col.length; i += 5) slots.push(col.slice(i, i + 5)); }
    const pos = {}, n = slots.length;
    slots.forEach((col, ci) => {
      const x = n === 1 ? W / 2 : 80 + (ci * (W - 160)) / (n - 1);
      const off = (ci % 2) * 26;                                  // stagger neighbouring columns
      col.forEach((id, ri) => { pos[id] = { x, y: col.length === 1 ? H / 2 + off - 13 : 64 + off + (ri * (H - 150)) / (col.length - 1), cx: x, cy: H / 2 }; });
    });
    return pos;
  }
  function curveP(pa, pb, seed) {
    const mx = (pa.x + pb.x) / 2, my = (pa.y + pb.y) / 2, dx = pb.x - pa.x, dy = pb.y - pa.y, len = Math.hypot(dx, dy) || 1;
    const k = (seed % 2 ? 1 : -1) * Math.min(40, len * 0.12), cx = mx - (dy / len) * k, cy = my + (dx / len) * k;
    return `M${pa.x.toFixed(1)},${pa.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${pb.x.toFixed(1)},${pb.y.toFixed(1)}`;
  }
  function buildIncMap(model) {
    const svg = $("#incMap"); svg.textContent = "";
    const pos = incLayout(model), gL = sv("g"), gH = sv("g"), gS = sv("g"); svg.append(gL, gH, gS);
    const links = model.links.map(([a, b], i) => { const p = sv("path", { d: curveP(pos[a], pos[b], i), class: "link" }); gL.append(p); return { a, b, el: p, i }; });
    const st = {};
    for (const m of model.machines) {
      const p = pos[m.id], kind = m.critical ? "critical" : !m.isolatable ? "medical" : /^(pc|ws)/.test(m.id) ? "workstation" : "server";
      const g = sv("g", { class: `st kind-${kind}`, transform: `translate(${p.x},${p.y})` }), mv = sv("g", { class: "st-move" });
      mv.append(sv("circle", { class: "pulse", r: 18 }), sv("circle", { class: "ring", r: 23 }), sv("circle", { class: "wall", r: 25 }));
      if (kind === "workstation") mv.append(sv("rect", { class: "body", x: -13, y: -10, width: 26, height: 18, rx: 2 }), sv("path", { class: "glyph", d: "M-5,13H5" }));
      else if (kind === "critical") mv.append(sv("rect", { class: "body", x: -16, y: -16, width: 32, height: 32, rx: 3 }), sv("path", { class: "glyph", d: "M-8,-6H8M-8,0H8M-8,6H8" }));
      else if (kind === "medical") mv.append(sv("circle", { class: "body", r: 14 }), sv("path", { class: "glyph", d: "M-6,0H6M0,-6V6" }));
      else mv.append(sv("rect", { class: "body", x: -13, y: -13, width: 26, height: 26, rx: 3 }), sv("path", { class: "glyph", d: "M-6,-4H6M-6,4H6" }));
      const lab = sv("text", { class: "label", y: kind === "critical" ? 34 : 31 }); lab.textContent = m.id.length > 18 ? m.id.slice(0, 17) + "…" : m.id; mv.append(lab);
      const tt = sv("title"); tt.textContent = `${m.id} — ${m.role}`; g.append(mv, tt);
      gS.append(g); st[m.id] = { g, mv, p };
    }
    return { pos, links, st, gH };
  }
  function incApply(c, step, decided) {
    for (const { g, mv } of Object.values(c.st)) { g.setAttribute("class", g.getAttribute("class").split(" ").filter((x) => x === "st" || x.startsWith("kind-")).join(" ")); mv.style.transform = ""; }
    for (const l of c.links) l.el.setAttribute("class", "link");
    const hacked = new Set(Object.keys(step.risk)), iso = new Set(decided ? step.isolate : []), seg = new Set(decided ? step.segment : []);
    for (const id of hacked) if (c.st[id]) c.st[id].g.classList.add("is-hacked");
    for (const id of seg) if (c.st[id]) c.st[id].g.classList.add("is-segmented");
    for (const id of iso) if (c.st[id]) {
      c.st[id].g.classList.add("is-isolated");
      const p = c.st[id].p; const dy = p.y - p.cy || -1; c.st[id].mv.style.transitionDelay = Math.round(p.x / 1000 * 300) + "ms";
      c.st[id].mv.style.transform = `translate(0px, ${Math.sign(dy) * 16}px)`;
    }
    c.gH.textContent = "";
    for (const l of c.links) {
      if (iso.has(l.a) || iso.has(l.b)) l.el.classList.add("is-cut"); else if (seg.has(l.a) || seg.has(l.b)) l.el.classList.add("is-walled");
      if (hacked.has(l.a) && hacked.has(l.b)) c.gH.append(sv("path", { d: l.el.getAttribute("d"), class: "hop" + (iso.has(l.a) || iso.has(l.b) || seg.has(l.a) || seg.has(l.b) ? " is-stopped" : reduced() ? "" : " is-draw") }));
    }
  }
  const FLOOR_RX = [[/destructive/i, "floor.destructive"], [/neighbour/i, "floor.neighbour"], [/costs no service/i, "floor.free"],
    [/owner/i, "floor.owner"], [/first hop/i, "floor.immune"], [/segment/i, "floor.critical"]];
  const floorText = (r) => { for (const [rx, k] of FLOOR_RX) if (rx.test(r)) return t(k); return r; };

  function incCard(step, i, n, fault) {
    const box = $("#incCard"); box.textContent = "";
    box.append(el("p", { class: "eyebrow", text: t("real.moment", { i: i + 1, n }) }));
    if (fault) box.append(el("div", { class: "fault-banner mt2", text: t("real.fault") }));
    const stat = el("div", { class: "status mt3" }); box.append(stat);
    statusBlock(stat, step.status, S.lang === "ar" ? step.status_ar : step.status);
    stat.append(el("span", { class: "status-sub", text: `${step.status} · ${step.fallback ? "fail-safe" : (step.method || "")} · ${nf(step.ms, 1)} ms · audit ${step.audit}` }));
    box.append(el("p", { class: "desc mt3", text: step.description }));
    const vs = el("div", { class: "vs" }); box.append(vs);
    vs.append(el("p", { class: "eyebrow", text: t("real.vs") }));
    const a = step.acrs_down.length, f = step.full_down.length, mx = Math.max(1, a, f);
    for (const [k, v, me] of [["vs.acrs", a, true], ["vs.full", f, false]]) {
      const fl = el("span", { class: "fl" });
      vs.append(el("div", { class: "vs-row" + (me ? " me" : "") }, [el("span", { text: t(k) }), el("span", { class: "tr" }, [fl]), el("b", { text: nf(v) })]));
      requestAnimationFrame(() => requestAnimationFrame(() => { fl.style.transform = `scaleX(${Math.max(0.015, v / mx)})`; }));
    }
    const ul = el("ul", { class: "actions-list mt3" });
    const join = (xs) => xs.length ? xs.join(", ") : t("none");
    ul.append(el("li", {}, [el("span", { text: "" }), el("div", {}, [el("span", { class: "k", text: t("act.iso") }), el("span", { class: "muted mono xs", text: join(step.isolate) })])]));
    ul.append(el("li", {}, [el("span", { text: "" }), el("div", {}, [el("span", { class: "k", text: t("act.seg") }), el("span", { class: "muted mono xs", text: join(step.segment) })])]));
    box.append(ul);
    if (step.floor.length) {
      const fl = el("ul", { class: "floor" });
      for (const r of step.floor.slice(0, 5)) fl.append(el("li", {}, [el("b", { class: "mono", text: r.machine + ": " }), el("span", { text: floorText(r.reason) })]));
      box.append(fl);
    }
  }
  function termLine(l) {
    const body = $("#termBody");
    const li = el("li", { class: `k-${l.kind} ${l.ok === true ? "ok" : l.ok === false ? "bad" : ""}` }, [
      l.audit ? el("span", { class: "h", text: "#" + l.audit }) : null, el("span", { class: "tx", text: l.text }), l.out ? el("span", { class: "o", text: l.out }) : null]);
    body.append(li); body.scrollTop = body.scrollHeight;
  }
  async function runIncident(auto = false) {
    if (auto !== true) auto = false;
    const R = S.real, my = ++R.token, btn = $("#runBtn"); busy(btn, true);
    const vsw = $("#verdictSweep"); vsw.className = "verdict-sweep"; vsw.textContent = "";
    let r;
    try { r = await api("/api/incident", { id: R.id, mode: R.mode }); } catch (e) { toast(e.message); busy(btn, false); return; }
    busy(btn, false); R.run = r;
    const c = buildIncMap(r.model);
    const mbox = $("#moments"); mbox.textContent = "";
    const mos = r.steps.map((s) => { const m = el("div", { class: "mo" }, [el("i"), el("span", { text: s.moment })]); mbox.append(m); return m; });
    $("#incSummary").hidden = true;
    const term = $("#term"), body = $("#termBody"); body.textContent = ""; term.hidden = R.mode !== "fault";
    if (!reduced()) document.querySelector(".real-grid").scrollIntoView({ behavior: "smooth", block: "start" });
    const sysLines = r.terminal.filter((l) => l.kind !== "cmd"), cmdLines = r.terminal.filter((l) => l.kind === "cmd");
    const alive = () => my === R.token && S.view === "real";
    if (!auto && AT.on) attractStop();
    for (let i = 0; i < r.steps.length; i++) {
      if (!alive()) return;
      const s = r.steps[i], fault = R.mode === "fault" && s.fallback;
      mos.forEach((m, k) => m.classList.toggle("is-on", k === i));
      incApply(c, s, false);
      await wait(700);
      const wrap = $("#incWrap"); wrap.classList.remove("is-scanning"); void wrap.offsetWidth; wrap.classList.add("is-scanning");
      if (fault) { const ff = $("#faultFlash"); ff.classList.remove("is-on"); void ff.offsetWidth; ff.classList.add("is-on");
        for (const l of sysLines.slice(0, 2)) { termLine(l); await wait(380); } }
      await wait(450);
      if (!alive()) return;
      incApply(c, s, true); incCard(s, i, r.steps.length, fault);
      if (fault) for (const l of sysLines.slice(2, 4)) { await wait(550); termLine(l); }
      mos[i].classList.remove("is-on"); mos[i].classList.add(fault ? "is-fault" : "is-done");
      await wait(fault ? 1500 : 1300);
    }
    if (R.mode === "fault") {
      for (const l of cmdLines) { if (!alive()) return; termLine(l); await wait(l.text.includes("approve") || l.text.includes("restore") ? 140 : 420); }
      for (const l of sysLines.slice(4)) { termLine(l); await wait(300); }
    }
    if (!alive()) return;
    const last = r.steps[r.steps.length - 1], contained = last.status === "CONTAINED" || last.status === "CONTAINED_PENDING_APPROVAL";
    const up = r.model.services.length - last.acrs_down.length;
    vsw.className = "verdict-sweep" + (contained ? "" : " human"); vsw.textContent = "";
    vsw.append(el("b", { text: contained ? t("verdict.ok") : t("verdict.human") }),
      el("span", { text: `${up}/${r.model.services.length} services up · ${r.totals.unsafe} unsafe · audit ${r.audit_ok ? "intact" : "broken"}` }));
    requestAnimationFrame(() => vsw.classList.add("is-on"));
    await wait(2600); if (!alive()) return;
    vsw.className = "verdict-sweep is-off";
    incSummary(r);
    if (!auto) $("#incSummary").scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "nearest" });
  }
  function incSummary(r) {
    const box = $("#incSummary"); box.textContent = ""; box.hidden = false;
    const last = r.steps[r.steps.length - 1];
    box.append(el("p", { class: "eyebrow", text: t("real.sum") }));
    const grid = el("div", { class: "sum-grid" }); box.append(grid);
    const card = (v, small, k, good) => grid.append(el("div", { class: "sum" }, [el("span", { class: "v" + (good ? " good" : "") }, [document.createTextNode(v), small ? el("small", { text: small }) : null]), el("span", { class: "k", text: k })]));
    card(nf(last.acrs_down.length), " / " + nf(last.full_down.length), t("sum.final"), last.acrs_down.length <= last.full_down.length);
    card(nf(r.totals.acrs_down), " / " + nf(r.totals.full_down), t("sum.total"), r.totals.acrs_down <= r.totals.full_down);
    card(nf(r.totals.unsafe + r.totals.silent), "", t("sum.unsafe"), r.totals.unsafe + r.totals.silent === 0);
    card(nf(r.audit_entries), "", t("sum.audit"), r.audit_ok);
    const ul = el("ul", { class: "checks" }); box.append(ul);
    const chk = (ok, k, vars) => ul.append(el("li", { class: ok ? "" : "no", text: t(k, vars) }));
    chk(r.totals.unsafe === 0, "chk.safe");
    chk(r.audit_ok, "chk.audit", { n: r.audit_entries });
    if (r.mode === "fault") {
      const st = r.steps.find((s) => s.restart), rec = r.recovery || {};
      if (st) chk(st.restart.released.length === 0 && st.restart.audit_ok, "chk.restart", { n: st.restart.isolated.length });
      chk(r.steps.some((s) => s.fallback), "chk.fallback");
      if (rec.refused_premature_readmit !== null && rec.refused_premature_readmit !== undefined) chk(rec.refused_premature_readmit, "chk.readmit");
      if (rec.pending_two_person) chk(true, "chk.two", { n: rec.pending_two_person });
      if (rec.closed) chk(true, "chk.immune");
      if (rec.replay) chk(rec.replay.services_down_after <= rec.replay.services_down_before, "chk.replay", { a: rec.replay.services_down_after, b: rec.replay.services_down_before });
    }
  }

  // ------------------------------------------------------------------------------------------- 1. break it
  const genuinePicks = () => S.picks.filter((p) => !p.forged).map((p) => p.id);
  function canReach(id) {
    const g = genuinePicks();
    if (!g.length) return S.M[id].entry;
    return S.M[id].entry || g.some((x) => (S.adj[x] || []).includes(id));
  }
  function setHint(key, tone) { const h = $("#hint"); h.textContent = t(key); h.dataset.tone = tone || ""; }

  function onPick(id) {
    const i = S.picks.findIndex((p) => p.id === id);
    if (i >= 0) { S.picks.splice(i, 1); }
    else {
      if (S.picks.length >= 20) { setHint("hint.max", "warn"); return; }
      if (S.mode === "real" && !canReach(id)) {
        const g = S.maps.main.st[id].g; g.classList.remove("is-refused"); void g.getBBox(); g.classList.add("is-refused");
        setHint("hint.notlinked", "warn"); return;
      }
      S.picks.push({ id, risk: S.risk, forged: S.mode === "forged" });
    }
    S.last = null;
    renderPicks();
  }

  function renderPicks() {
    const c = S.maps.main; resetMap(c);
    const g = genuinePicks(), gs = new Set(g);
    S.picks.forEach((p, k) => {
      cls(c, p.id, p.forged ? "is-forged" : "is-hacked");
      const o = sv("g", { class: "order", transform: "translate(0,-27)" });
      o.append(sv("circle", { r: 8 })); const tx = sv("text", { y: 3.5 }); tx.textContent = String(k + 1); o.append(tx);
      c.st[p.id].mv.append(o);
    });
    drawHops(c, g);
    if (S.mode === "real") {
      for (const m of S.model.machines) {
        if (!gs.has(m.id) && !S.picks.some((p) => p.id === m.id) && !canReach(m.id)) cls(c, m.id, "is-dim");
      }
      for (const l of c.links) if ((gs.has(l.a) && !gs.has(l.b)) || (gs.has(l.b) && !gs.has(l.a))) l.el.classList.add("is-next");
    }
    const box = $("#picks"); box.textContent = "";
    for (const p of S.picks) {
      const rm = el("button", { "aria-label": (S.lang === "ar" ? "إزالة " : "Remove ") + mname(p.id), text: "×" });
      rm.addEventListener("click", () => onPick(p.id));
      box.append(el("span", { class: "pick" + (p.forged ? " is-forged" : "") }, [
        el("span", { text: `${mname(p.id)} · ${p.risk}${p.forged ? (S.lang === "ar" ? " · مزوّر" : " · forged") : ""}` }), rm]));
    }
    $("#picksEmpty").hidden = S.picks.length > 0;
    $("#decideBtn").disabled = S.picks.length === 0;
    $("#decisionPanel").hidden = true;
    setEcg(S.ecg.main, []);
    if (S.mode === "forged") setHint("hint.forged"); else setHint(g.length ? "hint.next" : "hint.start");
    renderSaveWhat();
  }

  const attackBody = () => ({
    hacked: Object.fromEntries(S.picks.map((p) => [p.id, p.risk])),
    forged: S.picks.filter((p) => p.forged).map((p) => p.id),
  });

  const ICON = {
    CONTAINED: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    ESCALATED: '<circle cx="12" cy="8" r="3.2"/><path d="M5.5 19.5a6.5 5.5 0 0 1 13 0"/>',
    CONTAINED_PENDING_APPROVAL: '<circle cx="12" cy="8" r="3.2"/><path d="M5.5 19.5a6.5 5.5 0 0 1 13 0"/>',
    NOT_CONTAINED: '<path d="M12 6v7M12 17.5v.5"/>', REJECTED: '<path d="M7 7l10 10M17 7L7 17"/>',
  };
  function statusBlock(box, status, text) {
    box.textContent = ""; box.dataset.s = status;
    const mark = el("div", { class: "status-mark" });
    const s = sv("svg", { viewBox: "0 0 24 24", "aria-hidden": "true" }); s.innerHTML = ICON[status] || ICON.NOT_CONTAINED;
    mark.append(s); box.append(mark, el("p", { class: "status-text", text }));
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, reduced() ? 0 : ms));
  async function decide() {
    const btn = $("#decideBtn"); busy(btn, true);
    const wrap = $("#mapWrap");
    try {
      const body = attackBody();
      if (S.model.config.agent && $("#liveToggle").checked) body.live = true;
      wrap.classList.remove("is-scanning"); void wrap.offsetWidth; wrap.classList.add("is-scanning");
      const [d] = await Promise.all([api("/api/decide", body), wait(520)]);   // the scan is presentation; ms below is measured
      S.last = { d, ...attackBody() };
      S.maps.main.stagger = true;
      showDecision(true);
      S.maps.main.stagger = false;
      setHint("hint.done");
    } catch (e) { toast(e.message); } finally { busy(btn, false); }
  }

  async function sha256hex(obj) {
    try {
      const sorted = (o) => Array.isArray(o) ? o.map(sorted) : o && typeof o === "object"
        ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sorted(o[k])])) : o;
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(sorted(obj))));
      return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (e) { return ""; }
  }

  function pipeline(d, animate) {
    const ol = $("#pipe"); ol.textContent = "";
    const floorN = (d.floor || []).length;
    const pend = d.status !== "CONTAINED";
    const steps = [
      ["pipe.alert", `${Object.keys(S.last.hacked).length} ⟶`],
      ["pipe.floor", floorN ? `+${floorN}` : "0"],
      ["pipe.solver", d.fallback ? "fail-safe" : String(d.solver || "").replace(/^v12 floor \+ /, "")],
      ["pipe.gate", d.status === "CONTAINED" ? "PASS" : d.status === "ESCALATED" ? "HUMAN" : d.status],
      ["pipe.sign", d.pq_signature ? "✓ " + d.pq_signature.length / 2 + " B" : (d.signature ? "HMAC ✓" : "—")],
    ];
    const lis = steps.map(([k, v], i) => {
      const li = el("li", {}, [el("span", { class: "pd" }), el("span", { text: t(k) }), el("span", { class: "pt", text: v })]);
      if (i === 3 && pend) li.dataset.warn = "1";
      ol.append(li); return li;
    });
    const on = (li) => li.classList.add(li.dataset.warn ? "is-warn" : "is-on", "is-on");
    if (!animate || reduced()) { lis.forEach(on); return; }
    lis.forEach((li, i) => setTimeout(() => on(li), 90 + i * 130));
  }

  function showDecision(animate = false) {
    const { d, hacked, forged } = S.last;
    applyDecision(S.maps.main, hacked, forged, d.hassan);
    setEcg(S.ecg.main, d.hassan.services_down);
    $("#decisionPanel").hidden = false;
    pipeline(d, animate);
    statusBlock($("#status"), d.status, S.lang === "ar" ? d.status_ar : d.status_en);
    $("#status").append(el("span", { class: "status-sub", text: `${d.status} · ${d.engine || "v9"} · ${nf(d.ms, 1)} ms` }));
    const met = $("#metrics"); met.textContent = "";
    const m = (v, k, tone, unit) => {
      const vEl = el("span", { class: "v " + (tone || "") }); const n = el("span", { text: animate ? "0" : nf(v, unit === "ms" ? 1 : 0) });
      vEl.append(n); if (unit) vEl.append(el("small", { text: unit }));
      met.append(el("div", { class: "metric" }, [vEl, el("span", { class: "k", text: t(k) })]));
      if (animate) countTo(n, v, unit === "ms" ? 1 : 0);
    };
    const after = d.after_approval_down || d.hassan.services_down;
    m(d.hassan.services_down.length, "m.down", d.hassan.services_down.length ? "bad" : "good");
    m(after.length, "m.after", after.length ? "bad" : "good");
    m(Math.max(0, d.full_isolation.patient_minutes - d.hassan.patient_minutes), "m.pm");
    m(d.ms, "m.ms", "", "ms");
    const vs = $("#vs"); vs.textContent = "";
    vs.append(el("p", { class: "eyebrow", text: t("vs.title") }));
    const full = d.full_isolation.services_down.length, mine = d.hassan.services_down.length, mx = Math.max(1, full, mine);
    for (const [k, v, me] of [["vs.acrs", mine, true], ["vs.full", full, false]]) {
      const fl = el("span", { class: "fl" });
      vs.append(el("div", { class: "vs-row" + (me ? " me" : "") }, [el("span", { text: t(k) }), el("span", { class: "tr" }, [fl]), el("b", { text: nf(v) })]));
      const s = `scaleX(${Math.max(0.015, v / mx)})`;
      if (animate && !reduced()) requestAnimationFrame(() => requestAnimationFrame(() => { fl.style.transform = s; })); else fl.style.transform = s;
    }
    const fl = $("#floor"); fl.textContent = "";
    for (const r of (d.floor || [])) fl.append(el("li", { class: "k-" + r.kind }, [el("b", { text: mname(r.machine) + ": " }), el("span", { text: S.lang === "ar" ? r.ar : r.en })]));
    const seal = $("#seal"); seal.textContent = "";
    const row = (k, v, ok) => seal.append(el("b", { text: k }), el("span", { class: ok ? "ok" : "", text: v }));
    row(t("seal.engine"), `${d.engine || "v9"} · ${d.solver || ""}`);
    row(t("seal.hmac"), (d.signature || "").slice(0, 24) + "…", true);
    if (d.pq_signature) row(t("seal.pq"), d.pq_signature.slice(0, 24) + `… (${d.pq_signature.length / 2} B)`, true);
    const shaRow = el("span", { text: "…" }); seal.append(el("b", { text: t("seal.cert") }), shaRow);
    sha256hex(d.certificate).then((h) => { shaRow.textContent = h ? h.slice(0, 24) + "…" : "—"; });
    $("#mapHud").textContent = "";
    $("#mapHud").append(el("span", {}, [el("b", { text: d.engine || "v9" }), document.createTextNode(" engine")]),
      el("span", {}, [document.createTextNode("decision "), el("b", { text: nf(d.ms, 1) + " ms" })]));
    const ul = $("#actions"); ul.textContent = "";
    const lists = [
      ["isolate", S.lang === "ar" ? "عزل كامل" : "Isolate", d.hassan.isolate],
      ["segment", S.lang === "ar" ? "تجزئة: تبقى الخدمة وتُقطع الحركة الجانبية" : "Segment: keeps serving, lateral movement cut", d.hassan.segment],
      ["restrict", S.lang === "ar" ? "تقييد: قطع قناة المهاجم فقط" : "Restrict: cut the attacker's channel only", d.hassan.restrict],
    ];
    if (d.hassan.held.length) lists.push(["held", S.lang === "ar" ? "محجوز لقرار البشر" : "Held for humans", d.hassan.held]);
    const dot = { isolate: "var(--isolate)", segment: "var(--segment)", restrict: "var(--attack)", held: "var(--human)" };
    for (const [k, label, ids] of lists) {
      const sw = sv("svg", { viewBox: "0 0 22 22", width: 22, height: 22, "aria-hidden": "true" });
      sw.append(sv("rect", { x: 5, y: 7, width: 12, height: 12, rx: 2, fill: dot[k] }));
      ul.append(el("li", {}, [sw, el("div", {}, [el("span", { class: "k", text: label }),
        el("span", { class: "muted", text: ids.length ? ids.map(mname).join(S.lang === "ar" ? "، " : ", ") : t("none") })])]));
    }
    const esc = $("#escalations"); esc.textContent = "";
    const groups = new Map();
    for (const e of d.escalations) {
      const k = S.lang === "ar" ? e.ar : e.en;
      if (!groups.has(k)) groups.set(k, []);
      for (const x of String(e.target).split(",")) if (x && x !== "*") groups.get(k).push(x);
    }
    for (const [k, ids] of groups) esc.append(el("div", { class: "esc" }, [el("strong", { text: k }),
      ids.length ? el("span", { class: "xs", text: " — " + [...new Set(ids)].map(mname).join(S.lang === "ar" ? "، " : ", ") }) : null]));
    const why = $("#why"); why.textContent = "";
    for (const w of (S.lang === "ar" ? d.card.why : [])) why.append(el("li", { text: w }));
    if (S.lang === "en") why.append(el("li", { class: "mono xs", text: d.card_en }));
    const cfg = S.model.config;
    const dev = Math.abs(cfg.solver_budget_s - cfg.evaluated_solver_budget_s) > 1e-9 ? t("ms.dev", { e: cfg.evaluated_solver_budget_s }) : "";
    $("#msLine").textContent = t("ms.line", { solver: d.fallback ? `fail-safe (${d.fallback})` : d.solver, b: cfg.solver_budget_s, dev, ttl: nf(d.expires_in_s) });
    setImg("#receiptQr", d.receipt_qr, d.receipt);
    if (d.lab) renderLab(d.lab);
    renderVerify(); renderSaveWhat();
  }

  // ------------------------------------------------------------------------------------------- lab (idea 10)
  function renderLab(lab) {
    const box = $("#labBody"); box.textContent = "";
    if (!lab || lab.ok === false || lab.connected === false) { box.append(el("p", { text: t("lab.off") + (lab && lab.error ? ` (${lab.error})` : "") })); return; }
    box.append(el("p", { text: t("lab.mode", { m: lab.mode === "apply" ? t("lab.apply") : t("lab.dry") }) }));
    if (lab.rules) box.append(el("p", { class: "mono xs", text: t("lab.rules", { n: lab.rules.length, ms: lab.ms, t: lab.twin_ok === null ? "—" : lab.twin_ok ? "✓" : "✗" }) }));
    if (lab.ignored_not_in_lab && lab.ignored_not_in_lab.length) box.append(el("p", { class: "xs", text: t("lab.ign", { l: lab.ignored_not_in_lab.map(mname).join("، ") }) }));
    const p = lab.probe; if (!p) return;
    const word = (v) => v === true ? t("lab.open") : v === false ? t("lab.closed") : t("lab.unk");
    const tbl = el("table", { class: "cmp" });
    tbl.append(el("tr", {}, [el("th", { text: "" }), el("th", { text: t("lab.clin") }), el("th", { text: t("lab.lat") }), el("th", { text: t("lab.c2") })]));
    for (const [m, v] of Object.entries(p.clinical_from_client)) {
      const lat = p.lateral_from_compromised[m]; const latOpen = lat ? Object.values(lat).some((x) => x === true) : null;
      const c2 = m in p.c2_from_compromised ? p.c2_from_compromised[m] : null;
      tbl.append(el("tr", {}, [el("td", { text: mname(m) }), el("td", { class: v ? "ok" : "bad", text: word(v) }),
        el("td", { class: latOpen ? "bad" : "", text: lat ? word(latOpen) : "—" }), el("td", { class: c2 ? "bad" : "", text: c2 === null ? "—" : word(c2) })]));
    }
    box.append(tbl);
  }
  async function pollLab() {
    if (!S.model.config.agent) return;
    try { const r = await api("/api/lab", {}); $("#labDot").classList.toggle("on", !!r.connected && r.ok !== false); }
    catch (e) { $("#labDot").classList.remove("on"); }
  }

  // ------------------------------------------------------------------------------------------- 2. two hospitals
  const PRESETS = {
    nurse: { hacked: { pc_nurse2: 8, ehr_app2: 8, ehr_db: 9 }, forged: [] },
    doc: { hacked: { pc_doc1: 8, pacs1: 8, pacs_store: 9 }, forged: [] },
    portal: { hacked: { pc_recep1: 8, web1: 8, ehr_app1: 8 }, forged: [] },
    forge: { hacked: { pc_recep2: 7, dc1: 9, ehr_db: 9 }, forged: ["dc1", "ehr_db"] },
  };
  function presetButtons(box, onChoose, withCurrent) {
    box.textContent = "";
    box.append(el("span", { class: "small muted", text: t("preset") }));
    const add = (key, label) => { const b = el("button", { class: "btn", text: label }); b.addEventListener("click", () => onChoose(key, b)); box.append(b); };
    if (withCurrent && S.picks.length) add("current", t("preset.current"));
    add("nurse", t("p.nurse")); add("doc", t("p.doc")); add("portal", t("p.portal")); add("forge", t("p.forge"));
  }
  const presetAttack = (k) => k === "current" ? attackBody() : JSON.parse(JSON.stringify(PRESETS[k]));
  function countTo(node, v, dec = 0) {
    if (reduced()) { node.textContent = nf(v, dec); return; }
    const t0 = performance.now(), dur = 900;
    const p = Math.pow(10, dec);
    const step = (now) => { const k = Math.min(1, (now - t0) / dur); node.textContent = nf(Math.round(v * (1 - Math.pow(1 - k, 3)) * p) / p, dec); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  async function runTwin(key, btn) {
    if (btn) busy(btn, true);
    try {
      const a = presetAttack(key);
      const d = await api("/api/decide", a);
      applyDecision(S.maps.full, a.hacked, a.forged, d.full_isolation);
      applyDecision(S.maps.hassan, a.hacked, a.forged, d.hassan);
      setEcg(S.ecg.full, d.full_isolation.services_down); setEcg(S.ecg.hassan, d.hassan.services_down);
      countTo($("#pmFull"), d.full_isolation.patient_minutes); countTo($("#pmHassan"), d.hassan.patient_minutes);
    } catch (e) { toast(e.message); } finally { if (btn) busy(btn, false); }
  }

  // ------------------------------------------------------------------------------------------- 3. judge vs machine
  function judgeInit() {
    const keys = ["nurse", "doc", "portal"];
    const a = S.picks.length ? attackBody() : presetAttack(keys[Math.floor(Math.random() * keys.length)]);
    S.judge = { a, iso: new Set(), seg: new Set(), running: false, left: 60, t0: 0 };
    const c = S.maps.judge; resetMap(c);
    applyDecision(c, a.hacked, a.forged, { isolate: [], segment: [] });
    $("#timer").textContent = "60"; $("#timer").classList.remove("is-low");
    $("#judgeStart").disabled = false; $("#judgeDone").disabled = true;
  }
  function judgePick(id) {
    const J = S.judge; if (!J || !J.running) return;
    if (J.iso.has(id)) { J.iso.delete(id); J.seg.add(id); } else if (J.seg.has(id)) J.seg.delete(id); else J.iso.add(id);
    cls(S.maps.judge, id, "is-judge-iso", J.iso.has(id)); cls(S.maps.judge, id, "is-judge-seg", J.seg.has(id));
  }
  function judgeStart() {
    const J = S.judge; J.running = true; J.t0 = performance.now();
    $("#judgeStart").disabled = true; $("#judgeDone").disabled = false;
    $("#judgeOut").textContent = "";
    $("#judgeOut").append(el("p", { class: "small", text: t("judge.lede") }));
    clearInterval(J.int);
    J.int = setInterval(() => {
      const left = Math.max(0, 60 - Math.floor((performance.now() - J.t0) / 1000));
      $("#timer").textContent = String(left); $("#timer").classList.toggle("is-low", left <= 10);
      if (left === 0) judgeDone();
    }, 250);
  }
  async function judgeDone() {
    const J = S.judge; if (!J.running) return; J.running = false; clearInterval(J.int);
    const secs = Math.min(600, (performance.now() - J.t0) / 1000);
    $("#judgeDone").disabled = true;
    try {
      const r = await api("/api/judge", { ...J.a, isolate: [...J.iso], segment: [...J.seg], seconds: Math.round(secs * 10) / 10 });
      const j = r.judge, h = r.hassan, box = $("#judgeOut"); box.textContent = "";
      const safeJ = !j.safety_violations.length, row = (k, a, b, ca = "", cb = "") =>
        el("tr", {}, [el("th", { text: t(k) }), el("td", { class: ca, text: a }), el("td", { class: cb, text: b })]);
      const tbl = el("table", { class: "cmp" }, [
        el("tr", {}, [el("th", { text: "" }), el("th", { text: t("judge.you") }), el("th", { text: t("judge.hassan") })]),
        row("judge.safe", safeJ ? t("judge.yes") : t("judge.no"), t("judge.yes"), safeJ ? "ok" : "bad", "ok"),
        row("judge.status", S.lang === "ar" ? j.status_ar : j.status_en, S.lang === "ar" ? h.status_ar : h.status_en),
        row("judge.down", nf(j.services_down.length), nf(h.hassan.services_down.length), j.services_down.length ? "bad" : "ok", h.hassan.services_down.length ? "bad" : "ok"),
        row("judge.pm", nf(j.patient_minutes), nf(h.hassan.patient_minutes)),
        row("judge.time", `${nf(secs, 1)} ${t("sec")}`, `${nf(h.ms, 1)} ${t("msu")}`),
      ]);
      box.append(tbl);
      if (!safeJ) box.append(el("p", { class: "small bad mt3", text: t("judge.viol") + " " + j.safety_violations.join("؛ ") }));
      if (j.open_paths.length) box.append(el("p", { class: "small mt2", text: t("judge.open") + " " + j.open_paths.map(([a, b]) => `${mname(a)} → ${mname(b)}`).join("، ") }));
      const again = el("button", { class: "btn mt3", text: t("judge.again") }); again.addEventListener("click", judgeInit); box.append(again);
      applyDecision(S.maps.judge, J.a.hacked, J.a.forged, h.hassan);
    } catch (e) { toast(e.message); }
  }

  // ------------------------------------------------------------------------------------------- 4. ransomware
  const RSTARTS = { pc_recep1: ["الاستقبال (بريد تصيّد)", "Reception (phishing email)"], pc_nurse3: ["جهاز تمريض", "Nurse PC"], vpn: ["بوابة VPN", "VPN gateway"] };
  async function ransomLoad(start, btn) {
    if (btn) busy(btn, true);
    try {
      const [none, full, hassan] = await Promise.all(["none", "full", "hassan"].map((p) => api("/api/spread", { start: [start], policy: p })));
      S.ransom = { none, full, hassan, tick: 0 };
      $("#tick").value = 0; ransomShow(0);
    } catch (e) { toast(e.message); } finally { if (btn) busy(btn, false); }
  }
  function ransomShow(tk) {
    const R = S.ransom; if (!R) return; R.tick = tk; $("#tickOut").textContent = `${tk}′`;
    const pairs = [["none", S.maps.rNone, "#encNone"], ["full", S.maps.rFull, "#encFull"], ["hassan", S.maps.rHassan, "#encHassan"]];
    for (const [k, c, out] of pairs) {
      const f = R[k].frames[tk]; resetMap(c);
      for (const id of f.infected) cls(c, id, "is-infected");
      const iso = new Set(f.isolate || []);
      for (const id of iso) {
        cls(c, id, "is-isolated");
      }
      for (const id of f.segment || []) cls(c, id, "is-segmented");
      for (const l of c.links) if (iso.has(l.a) || iso.has(l.b)) l.el.classList.add("is-cut");
      const svc = tk === 10 ? ` · ${nf(R[k].services_unavailable.length)} ${t("svc.down")}` : "";
      $(out).textContent = `${nf(f.infected.length)} ${t("enc")}${svc}`;
    }
  }
  function ransomPlay() {
    if (!S.ransom) return;
    clearInterval(S.ransom.int); let k = 0; ransomShow(0); $("#tick").value = 0;
    S.ransom.int = setInterval(() => { k += 1; if (k > 10) { clearInterval(S.ransom.int); return; } $("#tick").value = k; ransomShow(k); }, reduced() ? 60 : 650);
  }

  // ------------------------------------------------------------------------------------------- 5. quantum
  async function quantumLoad() {
    if (S.quantum) return;
    try { S.quantum = await api("/api/quantum"); } catch (e) { toast(e.message); return; }
    renderQuantum();
  }
  function renderQuantum() {
    const q = S.quantum; if (!q) return;
    const three = $("#qThree"); three.textContent = "";
    for (const [v, k] of [[q.p_best_real, "q.real"], [q.p_best_ideal, "q.ideal"], [q.p_best_random, "q.random"]])
      three.append(el("div", {}, [el("span", { class: "v", text: pct(v) }), el("span", { class: "k", text: t(k) })]));
    const bars = $("#bars"); bars.textContent = "";
    const max = q.rows[0].count;
    for (const r of q.rows) {
      const b = el("button", { class: "bar" + (r.optimal ? " is-opt" : ""), "aria-pressed": "false",
        "aria-label": `${r.bits}: ${r.count} / ${q.shots}` });
      const tr = el("span", { class: "track" }), fill = el("span", { class: "fill" });
      fill.style.width = "100%"; fill.style.transform = `scaleX(${Math.max(0.004, r.count / max)})`;
      tr.append(fill);
      b.append(el("code", { text: r.bits }), tr, el("span", { class: "pct", text: pct(r.count / q.shots) }));
      b.addEventListener("click", () => { $$(".bar", bars).forEach((x) => x.setAttribute("aria-pressed", "false")); b.setAttribute("aria-pressed", "true"); shot(r); });
      bars.append(b);
    }
    const n = S.model.evidence.numbers;
    $("#e9Line").textContent = t("q.e9line", { k: n.e9_optimal.value, n: n.e9_components.value, q: n.e9_qubits.value, b: n.e9_backend.value,
      b2: n.e9_fez_backend.value, k2: n.e9_fez_optimal.value, v: n.e9_milp.value });
  }
  function shot(r) {
    const q = S.quantum, box = $("#shotOut"); box.textContent = "";
    box.append(el("p", { class: "eyebrow", text: `${q.backend} · job ${q.job_id}` }));
    box.append(el("p", { class: "mono", text: r.bits }));
    box.append(el("p", { class: "small", text: `${nf(r.count)} ${t("q.shots", { n: nf(q.shots) })}` }));
    const tbl = el("table", { class: "cmp mt3" }, [
      el("tr", {}, [el("th", { text: t("q.iso") }), el("td", { text: r.isolate.length ? r.isolate.join(", ") : t("none") })]),
      el("tr", {}, [el("th", { text: t("q.cost") }), el("td", { class: r.optimal ? "ok" : "", text: `${nf(r.cost, 1)} · ${r.optimal ? t("q.optimal") : t("q.notopt")}` })]),
      el("tr", {}, [el("th", { text: t("q.gate") }), el("td", { text: `${r.gate === "CONTAINED" ? t("q.now") : t("q.esc")} (${r.gate})` })]),
    ]);
    box.append(tbl);
    if (r.isolate_now.length) box.append(el("p", { class: "small mt2", text: `${t("q.now")}: ${r.isolate_now.join(", ")}` }));
    if (r.escalations.length) box.append(el("div", { class: "esc mt2", text: `${t("q.esc")}: ${r.escalations.join("، ")}` }));
  }

  // ------------------------------------------------------------------------------------------- 6. verify
  function renderVerify() {
    const ta = $("#certText");
    if (!S.last) { ta.value = ""; ta.placeholder = t("v.none"); $("#verifyBtn").disabled = true; $("#verifyQr").hidden = true; return; }
    ta.value = JSON.stringify(S.last.d.certificate, null, 2);
    $("#verifyBtn").disabled = false;
    setImg("#verifyQr", S.last.d.receipt_qr, S.last.d.receipt);
    $("#verdict").textContent = "";
  }
  async function verifyNow() {
    const box = $("#verdict"); box.textContent = "";
    let cert;
    try { cert = JSON.parse($("#certText").value); } catch (e) { box.append(el("div", { class: "verdict bad", text: t("v.json") })); return; }
    if (!cert || typeof cert !== "object" || Array.isArray(cert)) { box.append(el("div", { class: "verdict bad", text: t("v.json") })); return; }
    try {
      const body = { hacked: S.last.hacked, certificate: cert, signature: S.last.d.signature };
      if (S.last.d.pq_signature) body.pq_signature = S.last.d.pq_signature;
      const r = await api("/api/verify", body);
      const msg = r.accepted ? t("v.ok") : !r.signature_ok ? t("v.badsig") : t("v.badcert");
      box.append(el("div", { class: "verdict " + (r.accepted ? "ok" : "bad"), text: msg }));
    } catch (e) { box.append(el("div", { class: "verdict bad", text: e.message })); }
  }

  // ------------------------------------------------------------------------------------------- 7. memory (idea 14)
  function renderSaveWhat() {
    const a = S.picks.length ? attackBody() : null;
    $("#saveWhat").textContent = a ? t("m.what", { list: Object.keys(a.hacked).map(mname).join(S.lang === "ar" ? "، " : ", ") }) : t("m.need");
    $("#saveBtn").disabled = !a;
  }
  async function memoryLoad() {
    try { S.attacks = (await api("/api/attacks")).attacks; } catch (e) { toast(e.message); return; }
    renderMemory();
  }
  function renderMemory(results) {
    const grid = $("#memGrid"); grid.textContent = "";
    if (!S.attacks.length) { grid.append(el("div", { class: "panel empty" }, [el("p", { text: t("m.empty") })])); return; }
    const byId = results ? Object.fromEntries(results.rows.map((r) => [r.id, r])) : {};
    for (const a of S.attacks) {
      const card = el("div", { class: "mem" });
      card.append(el("span", { class: "mem-name", text: a.name }));
      card.append(el("span", { class: "xs muted", text: Object.keys(a.hacked).map(mname).join(S.lang === "ar" ? "، " : ", ") }));
      const r = byId[a.id];
      const badges = el("div", { class: "row" });
      if (r) {
        badges.append(el("span", { class: "badge " + (r.pass ? "ok" : "bad"), text: r.pass ? t("m.pass") : t("m.fail") }));
        if (r.changed_since_saved) badges.append(el("span", { class: "badge", text: t("m.changed") }));
      } else if (a.broke_rules_when_saved && a.broke_rules_when_saved.length) {
        badges.append(el("span", { class: "badge bad", text: t("m.fail") }));
      }
      card.append(badges);
      const run = el("button", { class: "btn btn-primary", text: t("m.run") });
      run.addEventListener("click", () => {
        S.picks = Object.entries(a.hacked).map(([id, risk]) => ({ id, risk, forged: (a.forged || []).includes(id) }));
        show("break"); renderPicks(); decide();
      });
      const del = el("button", { class: "btn btn-quiet", text: t("m.del") });
      del.addEventListener("click", async () => {
        if (del.dataset.confirm !== "1") { del.dataset.confirm = "1"; del.textContent = S.lang === "ar" ? "اضغط للتأكيد" : "Tap to confirm"; return; }
        try { await api("/api/attacks/delete", { id: a.id }); memoryLoad(); } catch (e) { toast(e.message); }
      });
      card.append(el("div", { class: "row" }, [run, del]));
      grid.append(card);
    }
  }
  async function regress() {
    const btn = $("#regressBtn"); busy(btn, true);
    try {
      const r = await api("/api/attacks/regress", {});
      const out = $("#regressOut"); out.textContent = "";
      out.append(el("div", { class: "verdict " + (r.passed === r.total ? "ok" : "bad"), text: t("m.result", { p: nf(r.passed), t: nf(r.total), s: nf(r.seconds * 1000) }) }));
      renderMemory(r);
    } catch (e) { toast(e.message); } finally { busy(btn, false); }
  }
  async function saveAttack(ev) {
    ev.preventDefault();
    const name = $("#attackName").value.trim(), ok = $("#consent").checked;
    $("#nameErr").textContent = "";
    if (!name || name.length > 40) { $("#nameErr").textContent = t("err.name"); $("#attackName").focus(); return; }
    if (!ok) { $("#nameErr").textContent = t("err.consent"); return; }
    const btn = $("#saveBtn"); busy(btn, true);
    try {
      await api("/api/attacks/save", { name, consent: true, ...attackBody() });
      $("#attackName").value = ""; $("#consent").checked = false; toast(t("m.saved")); memoryLoad();
    } catch (e) { $("#nameErr").textContent = e.message; } finally { busy(btn, false); }
  }

  // ------------------------------------------------------------------------------------------- 8. story & evidence
  function mapHudIdle() {
    const h = $("#mapHud"); if (!h) return; h.textContent = "";
    h.append(el("span", {}, [el("b", { text: String(S.model.machines.length) }), document.createTextNode(" machines")]),
      el("span", {}, [el("b", { text: String(S.model.links.length) }), document.createTextNode(" links")]),
      el("span", {}, [el("b", { text: String(S.model.services.length) }), document.createTextNode(" services")]));
  }

  function renderStory() {
    const n = S.model.evidence.numbers, tl = $("#timeline"); tl.textContent = "";
    const hero = $("#heroNums"); hero.textContent = "";
    if (n.v12_corpus_auto_ratio) {
      const card = (v, cls, k, src) => hero.append(el("div", { class: "panel hud hero-num" }, [el("span", { class: "v " + cls }, v), el("span", { class: "k", text: k }), el("span", { class: "src", text: src })]));
      const f = (k) => n[k].file.split("/").slice(-2).join("/") + " → " + n[k].path.split(".").slice(-2).join(".");
      card([document.createTextNode(nf(100 * n.v12_corpus_auto_ratio.value, 0)), el("small", { text: "%" })], "good", t("hero.auto", { n: nf(n.v12_corpus_cases.value) }), f("v12_corpus_auto_ratio"));
      card([document.createTextNode(nf(n.v12_corpus_down.value)), el("small", { text: " / " + nf(n.v12_corpus_full_down.value) })], "good", t("hero.down", { f: nf(n.v12_corpus_full_down.value) }), f("v12_corpus_down"));
      card([document.createTextNode(nf(n.v12_corpus_unsafe.value))], "good", t("hero.unsafe"), f("v12_corpus_unsafe"));
      card([document.createTextNode(nf(n.v12_scale_1000_median_ms.value, 1)), el("small", { text: " ms" })], "", t("hero.ms"), f("v12_scale_1000_median_ms"));
    }
    const card = (k, kind, val, src) => tl.append(el("div", { class: "tl " + kind }, [
      el("span", { class: "eyebrow", text: t(kind === "fail" ? "tl.fail" : kind === "fix" ? "tl.fix" : "tl.conf") }),
      el("span", { class: "from-to", text: val }), el("p", { class: "small", text: t(k) }), el("p", { class: "xs muted mono", text: src })]));
    card("tl.v6", "fail", nf(n.v6_h1_ratio.value, 2), n.v6_h1_ratio.file.split("/").pop());
    card("tl.v7", "fix", nf(n.v7_h1_ratio.value, 3), n.v7_h1_ratio.file.split("/").pop());
    card("tl.v9", "conf", nf(n.v9_h60_ratio.value, 3), n.v9_h60_ratio.file.split("/").pop());
    card("tl.e7", "fail", pct(n.e7_p_best_real.value), n.e7_p_best_real.file.split("/").pop());
    card("tl.e8", "fix", pct(n.e8_p_best_real.value), n.e8_p_best_real.file.split("/").pop());
    card("tl.e9", "conf", `${n.e9_optimal.value}/${n.e9_components.value}`, n.e9_optimal.file.split("/").pop());
    const al = $("#align"); al.textContent = "";
    for (const [k, v] of t("al.rows")) al.append(el("div", { class: "align-row" }, [el("strong", { class: "mono small", text: k }), el("p", { class: "small", text: v })]));
    al.append(el("p", { class: "note mt3", text: t("al.note") }));
    const tb = $("#evTable"); tb.textContent = "";
    tb.append(el("tr", {}, [el("th", { text: t("ev.claim") }), el("th", { text: t("ev.value") }), el("th", { text: t("ev.src") })]));
    const fmt = (k) => {
      const v = n[k].value;
      if (k === "v12_corpus_auto_ratio") return pct(v, 1);
      if (k === "v12_scale_1000_median_ms") return nf(v, 2);
      if (/ratio|rate|detection|false_flags|p_best/.test(k)) return k.includes("ratio") ? nf(v, 3) : pct(v);
      if (k === "v9_ttc_p95_ms") return nf(v, 1);
      return typeof v === "number" ? nf(v) : String(v);
    };
    const rows = ["v12_corpus_auto_ratio", "v12_corpus_down", "v12_corpus_rule_down", "v12_corpus_full_down", "v12_corpus_unsafe",
      "v12_scale_1000_median_ms", "v12_pq_tamperings", "v7_h1_ratio", "v7_hassan_services_down", "v7_full_services_down", "v7_escalation_rate", "v9_h60_ratio", "v9_ttc_p95_ms",
      "v9_cert_rejected", "v9_guard_detection", "v9_guard_false_flags", "v9_twin_aborted", "v8_failsafe_crashes", "v8_cards_complete",
      "rw_h60_floor", "e8_p_best_real", "e9_optimal"];
    for (const k of rows) {
      let val = fmt(k);
      if (k === "v7_h1_ratio") val += ` (n = ${nf(n.v7_n.value)})`;
      if (k === "v8_cards_complete") val += ` / ${nf(n.v8_cards_total.value)}`;
      tb.append(el("tr", {}, [el("td", { text: t("ev." + k) }), el("td", { class: "mono", text: val }), el("td", { class: "src", text: `${n[k].file} → ${n[k].path}` })]));
    }
    const worst = Math.max(n.v8_forgery_worst_down_net12.value, n.v8_forgery_worst_down_net22.value);
    tb.append(el("tr", {}, [el("td", { text: t("ev.v8_forgery") }), el("td", { class: "mono", text: `${nf(worst)} (${nf(n.v8_forgery_sets_net12.value + n.v8_forgery_sets_net22.value)})` }),
      el("td", { class: "src", text: `${n.v8_forgery_worst_down_net12.file} → certificate_validity_random.*` })]));
    const lim = $("#limits"); lim.textContent = "";
    for (const l of t("limits")) lim.append(el("li", { text: l }));
    setImg("#repoQr", S.model.repo_qr, S.model.evidence.repo);
    $("#reproCmd").textContent = S.model.reproduce;
    $("#evStat").textContent = t("v.ev", { n: Object.keys(S.model.evidence.files).length });
  }

  // ------------------------------------------------------------------------------------------- shell
  function show(view) {
    S.view = view;
    for (const b of $$(".tab")) b.setAttribute("aria-selected", b.dataset.view === view ? "true" : "false");
    for (const v of $$(".view")) v.classList.toggle("is-active", v.id === "view-" + view);
    if (view === "real") realLoad();
    if (view === "twin") { presetButtons($("#twinPresets"), runTwin, true); runTwin(S.picks.length ? "current" : "nurse"); }
    if (view === "judge" && (!S.judge || !S.judge.running)) judgeInit();
    if (view === "ransom" && !S.ransom) ransomLoad("pc_recep1");
    if (view === "quantum") quantumLoad();
    if (view === "memory") memoryLoad();
    if (view === "verify") renderVerify();
    store.set("hassan-view", view);
  }

  function applyLang() {
    const html = document.documentElement;
    html.lang = S.lang; html.dir = S.lang === "ar" ? "rtl" : "ltr";
    for (const n of $$("[data-i18n]")) n.textContent = t(n.dataset.i18n);
    for (const n of $$("[data-i18n-aria]")) n.setAttribute("aria-label", t(n.dataset.i18nAria));
    $("#langBtn").textContent = S.lang === "ar" ? "EN" : "ع";
    $("#langBtn").setAttribute("aria-label", S.lang === "ar" ? "English" : "العربية");
    document.title = "ACRS";
  }

  function buildAll() {
    S.maps.main = buildMap($("#mapMain"), { interactive: true, onPick, packets: true });
    S.maps.full = buildMap($("#mapFull")); S.maps.hassan = buildMap($("#mapHassan"));
    S.maps.judge = buildMap($("#mapJudge"), { interactive: true, onPick: judgePick });
    S.maps.rNone = buildMap($("#mapNone")); S.maps.rFull = buildMap($("#mapRFull")); S.maps.rHassan = buildMap($("#mapRHassan"));
    S.ecg = { main: buildEcg($("#ecgMain")), full: buildEcg($("#ecgFull")), hassan: buildEcg($("#ecgHassan")) };
    legend(); renderPicks(); renderStory(); renderVerify(); renderSaveWhat(); packetsStart(); mapHudIdle();
    const rs = $("#ransomStarts"); rs.textContent = "";
    for (const [id, [ar, en]] of Object.entries(RSTARTS)) {
      const b = el("button", { class: "btn", text: S.lang === "ar" ? ar : en }); b.addEventListener("click", () => ransomLoad(id, b)); rs.append(b);
    }
    if (S.last) showDecision();
    if (S.quantum) renderQuantum();
    if (S.ransom) ransomShow(S.ransom.tick);
    if (S.real && S.real.cat) { renderSectors(); renderIncList(); }
    if (S.judge) { const J = S.judge; applyDecision(S.maps.judge, J.a.hacked, J.a.forged, { isolate: [], segment: [] });
      for (const id of J.iso) cls(S.maps.judge, id, "is-judge-iso"); for (const id of J.seg) cls(S.maps.judge, id, "is-judge-seg"); }
  }

  /* ACRS Box power-on: the mark draws itself, the real self-test streams in (values from the server), the hospital
     network assembles from scattered points into its floor plan and is armed, then the interface opens. ~5 s, skippable. */
  function bootSequence() {
    const box = $("#boot"), ol = $("#bootLines"), bar = $("#bootBar"), net = $("#bootNet"), armed = $("#bootArmed");
    let finished = false;
    const done = () => {
      if (finished) return; finished = true;
      box.classList.add("is-done"); document.removeEventListener("keydown", done); box.removeEventListener("pointerdown", done);
      S.booted = true; attractArm();
    };
    let seen = null; try { seen = sessionStorage.getItem("acrs-boot"); } catch (e) { /* private mode */ }
    if (reduced() || seen) { done(); return; }
    try { sessionStorage.setItem("acrs-boot", "1"); } catch (e) { /* fine */ }
    $("#bootSkip").textContent = t("boot.skip");
    const T = S.model.selftest || {};
    const okT = (c) => c ? ["st-ok", "OK"] : ["st-warn", "WARN"];
    const lines = [
      [t("bt.kernel"), ["st-ok", "OK"]],
      [t("bt.gate", { k: T.locked_ok, n: T.locked_n }), okT(T.locked_ok === T.locked_n)],
      [t("bt.pq", { b: T.pq_pk_bytes }), okT(!!T.pq_alg)],
      [t("bt.engine", { e: T.engine, b: S.model.config.solver_budget_s, f: T.fail_safe ?? 0, n: T.reference_attacks ?? 0 }), okT(!T.fail_safe)],
      [t("bt.net", { h: T.hosts, l: T.links, s: T.services }), ["st-ok", "OK"]],
      [t("bt.corpus", { n: T.incidents, r: T.incidents_real }), ["st-ok", "OK"]],
      [t("bt.ev", { n: T.evidence_files }), ["st-ok", "OK"]],
    ];
    ol.textContent = "";
    const t0 = performance.now();
    const lis = lines.map(([txt, [cls, word]]) => {
      const li = el("li", {}, [el("span", { class: "ts", text: "" }), el("span", { text: txt }), el("span", { class: cls, text: word })]);
      ol.append(li); return li;
    });
    // network constellation: real hospital positions, scattered first
    net.textContent = ""; net.setAttribute("class", "boot-net");
    const gL = sv("g"), gN = sv("g"); net.append(gL, gN);
    for (const [a, b] of S.model.links) { const p = sv("path", { class: "bn-link", d: curve(a, b).d }); gL.append(p); }
    const nodes = S.model.machines.map((m, i) => {
      const p = S.pos[m.id], r = m.critical ? 9 : 6;
      const c = sv("circle", { class: "bn-node" + (m.critical ? " crit" : !m.isolatable ? " med" : ""), cx: p.x, cy: p.y, r });
      const ang = (i * 137.5) * Math.PI / 180, rad = 260 + (i % 7) * 40;
      c.style.transform = `translate(${(600 + Math.cos(ang) * rad - p.x).toFixed(0)}px, ${(385 + Math.sin(ang) * rad * .6 - p.y).toFixed(0)}px)`;
      c.style.transitionDelay = (i * 14) + "ms";
      const ring = sv("circle", { class: "bn-ring", cx: p.x, cy: p.y, r: r + 10 }); ring.style.animationDelay = (i * 8) + "ms";
      gN.append(c, ring); return c;
    });
    const step = 300, base = 900;
    lis.forEach((li, i) => setTimeout(() => {
      li.firstChild.textContent = ((performance.now() - t0) / 1000).toFixed(2).padStart(5, " ");
      li.classList.add("is-on"); bar.style.transform = `scaleX(${(i + 1) / lis.length})`;
    }, base + i * step));
    setTimeout(() => net.classList.add("is-on"), 500);
    setTimeout(() => { for (const c of nodes) c.style.transform = ""; }, base + 2 * step);
    setTimeout(() => net.classList.add("is-linked"), base + 4 * step);
    const end = base + lis.length * step;
    setTimeout(() => { net.classList.add("is-armed"); armed.textContent = t("boot.armed"); armed.classList.add("is-on"); }, end + 200);
    setTimeout(done, end + 1500);
    document.addEventListener("keydown", done); box.addEventListener("pointerdown", done);
  }

  /* self-running demo: after 60 s without a touch, replay a real incident; any touch hands control back at once */
  const ATTRACT = [["07_hse_conti_2021", "fault"], ["01_bangladesh_bank_2016", "normal"], ["06_colonial_pipeline_2021", "normal"],
    ["02_wannacry_nhs_2017", "fault"], ["04_norsk_hydro_2019", "normal"], ["05_duesseldorf_hospital_2020", "fault"]];
  const AT = { timer: 0, on: false, k: 0, idle: 0 };
  function attractArm() {
    clearTimeout(AT.timer);
    AT.timer = setTimeout(attractStart, 60000);
  }
  function attractStop() {
    if (AT.on) { AT.on = false; $("#attract").hidden = true; if (S.real) S.real.token++; }
    document.body.classList.remove("kiosk-idle");
    attractArm();
    clearTimeout(AT.idle); AT.idle = setTimeout(() => { if (KIOSK) document.body.classList.add("kiosk-idle"); }, 3000);
  }
  async function attractStart() {
    if (!S.booted) return;
    AT.on = true; $("#attractText").textContent = t("attract.text"); $("#attract").hidden = false;
    show("real"); await realLoad();
    while (AT.on) {
      const [id, mode] = ATTRACT[AT.k++ % ATTRACT.length];
      const it = S.real.cat && S.real.cat.incidents.find((x) => x.id === id); if (!it) continue;
      S.real.group = it.group; renderSectors(); selectIncident(id);
      S.real.mode = mode; $$("[data-rmode]").forEach((x) => x.setAttribute("aria-pressed", x.dataset.rmode === mode ? "true" : "false"));
      await wait(1500); if (!AT.on) return;
      await runIncident(true);
      await wait(9000);
    }
  }
  const KIOSK = /[?&]kiosk=1/.test(location.search);

  async function boot() {
    applyLang();
    try {
      S.token = (await api("/api/session")).token;
      S.model = await api("/api/model");
    } catch (e) {
      const f = $("#fatal"); f.hidden = false; f.textContent = e.message; $("#boot").classList.add("is-done"); return;
    }
    S.M = Object.fromEntries(S.model.machines.map((m) => [m.id, m]));
    for (const [a, b] of S.model.links) { (S.adj[a] ||= []).push(b); (S.adj[b] ||= []).push(a); }
    for (const z of S.model.zones) for (const m of z.machines) S.zoneOf[m] = z.id;
    S.pos = layout();
    buildAll();
    bootSequence();
    $$(".tab").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
    $("#tabs").addEventListener("keydown", (e) => {
      const tabs = $$(".tab"), i = tabs.findIndex((x) => x.getAttribute("aria-selected") === "true");
      const fwd = (S.lang === "ar") ? "ArrowLeft" : "ArrowRight", back = (S.lang === "ar") ? "ArrowRight" : "ArrowLeft";
      if (e.key === fwd || e.key === back) { const j = (i + (e.key === fwd ? 1 : tabs.length - 1)) % tabs.length; tabs[j].focus(); show(tabs[j].dataset.view); }
    });
    $$(".seg button").forEach((b) => b.addEventListener("click", () => {
      S.mode = b.dataset.mode; $$(".seg button").forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false")); renderPicks();
    }));
    $("#risk").addEventListener("input", (e) => { S.risk = +e.target.value; $("#riskOut").textContent = e.target.value; });
    $("#clearBtn").addEventListener("click", () => { S.picks = []; S.last = null; renderPicks(); renderVerify(); });
    $("#decideBtn").addEventListener("click", decide);
    $("#toSave").addEventListener("click", () => { show("memory"); $("#attackName").focus(); });
    $("#toVerify").addEventListener("click", () => show("verify"));
    $("#judgeStart").addEventListener("click", judgeStart);
    $("#judgeDone").addEventListener("click", judgeDone);
    $("#ransomPlay").addEventListener("click", ransomPlay);
    $("#tick").addEventListener("input", (e) => { if (S.ransom) clearInterval(S.ransom.int); ransomShow(+e.target.value); });
    $("#verifyBtn").addEventListener("click", verifyNow);
    $("#restoreBtn").addEventListener("click", renderVerify);
    $("#regressBtn").addEventListener("click", regress);
    $("#saveForm").addEventListener("submit", saveAttack);
    $("#langBtn").addEventListener("click", () => { S.lang = S.lang === "ar" ? "en" : "ar"; store.set("hassan-lang", S.lang); applyLang(); buildAll(); show(S.view); });
    $("#themeBtn").addEventListener("click", () => {
      const light = document.documentElement.dataset.theme === "light";
      document.documentElement.dataset.theme = light ? "dark" : "light"; store.set("hassan-theme", document.documentElement.dataset.theme);
    });
    $("#brandEngine").textContent = S.model.config.engine || "v9";
    const tick = () => { const d = new Date(); $("#clock").textContent = d.toLocaleTimeString("en-GB", { hour12: false }); };
    const T0 = (S.model.selftest && S.model.selftest.started_at) ? S.model.selftest.started_at * 1000 : Date.now();
    const tick2 = () => { const s = Math.max(0, Math.floor((Date.now() - T0) / 1000)); $("#uptime").textContent = "UP " + [s / 3600, (s % 3600) / 60, s % 60].map((x) => String(Math.floor(x)).padStart(2, "0")).join(":"); };
    tick(); tick2(); setInterval(() => { tick(); tick2(); }, 1000);
    for (const ev of ["pointerdown", "keydown", "wheel", "touchstart"]) document.addEventListener(ev, () => { if (S.booted) attractStop(); }, { passive: true });
    document.addEventListener("pointermove", () => { if (KIOSK) { document.body.classList.remove("kiosk-idle"); clearTimeout(AT.idle); AT.idle = setTimeout(() => document.body.classList.add("kiosk-idle"), 3000); } }, { passive: true });
    if (document.fullscreenEnabled) {
      $("#fsBtn").hidden = false;
      $("#fsBtn").addEventListener("click", () => { if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen().catch(() => {}); });
    }
    if (S.model.config.agent) { $("#labPanel").hidden = false; $("#labChip").hidden = false; pollLab(); setInterval(pollLab, 10000); }
    $$("[data-rmode]").forEach((b) => b.addEventListener("click", () => {
      S.real.mode = b.dataset.rmode; $$("[data-rmode]").forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false"));
    }));
    $("#runBtn").addEventListener("click", runIncident);
    const v = store.get("hassan-view"); show(v && $("#view-" + v) ? v : "real");
  }

  const th = store.get("hassan-theme"); if (th === "light") document.documentElement.dataset.theme = "light";
  document.addEventListener("DOMContentLoaded", boot);
})();
