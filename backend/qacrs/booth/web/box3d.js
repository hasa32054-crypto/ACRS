/* ACRS Box — real-time 3D exploded view (three.js r170, vendored, offline).
   Six physical layers built from geometry (no downloaded models): touch screen, Raspberry Pi 5 board, seal & storage,
   network ports, backup battery, enclosure. app.js owns the pointer and the targets (BX.tu = open upward,
   BX.ts = fan out sideways, BX.tt = tilt); this module eases toward them and renders. Falls back to the CSS view if
   WebGL is missing. */
import * as THREE from "./vendor/three/three.module.min.js";
import { RoomEnvironment } from "./vendor/three/RoomEnvironment.js";
import { RoundedBoxGeometry } from "./vendor/three/RoundedBoxGeometry.js";

const C = { bg: 0x0d161c, ink: 0xe8f0f3, alive: 0x3fd49a, attack: 0xff5b3f, amber: 0xf3b544, blue: 0x2f7dd1 };

function canvasTex(w, h, draw) {
  const c = document.createElement("canvas"); c.width = w; c.height = h;
  draw(c.getContext("2d"), w, h);
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; t.anisotropy = 4; return t;
}
function mark(g, x, y, s, ink = "#E8F0F3") {           // the network-A logo
  g.save(); g.translate(x, y); g.scale(s, s); g.lineCap = "round";
  g.strokeStyle = ink; g.lineWidth = 14; g.beginPath(); g.moveTo(100, 30); g.lineTo(44, 170); g.moveTo(100, 30); g.lineTo(156, 170); g.stroke();
  g.strokeStyle = "#3FD49A"; g.beginPath(); g.moveTo(73, 114); g.lineTo(127, 114); g.stroke();
  g.restore();
}
const mat = (color, o = {}) => new THREE.MeshStandardMaterial({ color, roughness: 0.55, metalness: 0.1, ...o });
const box = (w, h, d, m, r = 0.02) => { const me = new THREE.Mesh(new RoundedBoxGeometry(w, h, d, 3, r), m); me.castShadow = true; me.receiveShadow = true; return me; };
const at = (o, x, y, z) => { o.position.set(x, y, z); return o; };

function screenLayer() {
  const g = new THREE.Group();
  g.add(box(3.5, 0.14, 2.35, mat(0x0b1115, { roughness: 0.35, metalness: 0.4 }), 0.08));
  const ui = canvasTex(1024, 680, (x, w, h) => {
    x.fillStyle = "#060B0E"; x.fillRect(0, 0, w, h);
    mark(x, 40, 34, 0.42); x.fillStyle = "#E8F0F3"; x.font = "700 46px sans-serif"; x.fillText("ACRS", 150, 86);
    x.fillStyle = "#3FD49A"; x.font = "500 22px monospace"; x.fillText("v12 · LIVE", 300, 84);
    x.fillStyle = "rgba(63,212,154,.16)"; x.strokeStyle = "rgba(63,212,154,.7)"; x.lineWidth = 3;
    x.beginPath(); x.roundRect(40, 140, 520, 96, 16); x.fill(); x.stroke();
    x.fillStyle = "#3FD49A"; x.font = "700 48px sans-serif"; x.fillText("CONTAINED", 70, 205);
    const bars = [[40, 290, 700, "#1A2A33"], [40, 340, 520, "#1A2A33"], [40, 390, 610, "#1A2A33"]];
    for (const [bx, by, bw, c] of bars) { x.fillStyle = c; x.beginPath(); x.roundRect(bx, by, bw, 22, 11); x.fill(); }
    x.fillStyle = "#3FD49A"; x.beginPath(); x.roundRect(40, 470, 120, 34, 8); x.fill();
    x.fillStyle = "#8A9AA4"; x.beginPath(); x.roundRect(180, 470, 560, 34, 8); x.fill();
    x.fillStyle = "#82959F"; x.font = "500 22px monospace"; x.fillText("ML-DSA-65 · audit chain intact", 40, 600);
    for (let i = 0; i < 9; i++) { x.fillStyle = i === 6 ? "#FF5B3F" : "#3FD49A"; x.beginPath(); x.arc(800 + (i % 3) * 56, 300 + Math.floor(i / 3) * 56, 14, 0, 7); x.fill(); }
  });
  const glass = new THREE.Mesh(new THREE.PlaneGeometry(3.2, 2.08), new THREE.MeshPhysicalMaterial({ map: ui, emissive: 0xffffff, emissiveMap: ui, emissiveIntensity: 0.9, roughness: 0.15, metalness: 0, clearcoat: 1 }));
  glass.rotation.x = -Math.PI / 2; at(glass, 0, 0.075, 0); g.add(glass);
  return g;
}
function piLayer() {
  const g = new THREE.Group();
  const pcbTex = canvasTex(1024, 680, (x, w, h) => {
    x.fillStyle = "#0B3A2B"; x.fillRect(0, 0, w, h);
    x.strokeStyle = "rgba(215,180,90,.35)"; x.lineWidth = 3;
    for (let i = 0; i < 26; i++) { x.beginPath(); const y = 120 + i * 18; x.moveTo(60, y); x.lineTo(300 + (i * 37) % 300, y); x.lineTo(360 + (i * 37) % 300, y + 40); x.stroke(); }
    x.fillStyle = "rgba(255,255,255,.75)"; x.font = "600 30px monospace"; x.fillText("RASPBERRY PI 5  ·  ACRS ENGINE v12", 60, 640);
  });
  const board = box(3.1, 0.07, 2.05, mat(0x0b3a2b, { map: pcbTex, roughness: 0.6 }), 0.06); g.add(board);
  g.add(at(box(0.62, 0.08, 0.62, mat(0xb8c2c6, { metalness: 0.9, roughness: 0.25 }), 0.03), -0.25, 0.08, -0.05));   // SoC heat spreader
  g.add(at(box(0.46, 0.06, 0.62, mat(0x15191b), 0.02), 0.35, 0.07, -0.05));                                         // RAM
  g.add(at(box(0.55, 0.42, 0.55, mat(0xc9cfd2, { metalness: 0.85, roughness: 0.3 }), 0.02), 1.22, 0.24, -0.55));      // USB stack
  g.add(at(box(0.55, 0.42, 0.55, mat(0xc9cfd2, { metalness: 0.85, roughness: 0.3 }), 0.02), 1.22, 0.24, 0.1));
  g.add(at(box(0.6, 0.36, 0.5, mat(0xc9cfd2, { metalness: 0.85, roughness: 0.3 }), 0.02), 1.22, 0.21, 0.72));        // Ethernet
  const pins = new THREE.InstancedMesh(new THREE.BoxGeometry(0.035, 0.18, 0.035), mat(0xd7b45a, { metalness: 0.9, roughness: 0.25 }), 40);
  const m4 = new THREE.Matrix4();
  for (let i = 0; i < 40; i++) { m4.makeTranslation(-1.3 + (i % 20) * 0.1, 0.12, -0.92 + Math.floor(i / 20) * 0.1); pins.setMatrixAt(i, m4); }
  pins.castShadow = true; g.add(pins);
  const fan = new THREE.Mesh(new THREE.CylinderGeometry(0.32, 0.32, 0.06, 40), mat(0x111518, { roughness: 0.4 }));
  at(fan, -0.25, 0.16, -0.05); fan.castShadow = true; g.add(fan); g.userData.fan = fan;
  return g;
}
function sealLayer() {
  const g = new THREE.Group();
  g.add(box(3.0, 0.06, 1.95, mat(0x101a1f), 0.05));
  const nvme = new THREE.Group(); nvme.add(box(2.0, 0.04, 0.42, mat(0x0d2a20), 0.02));
  for (let i = 0; i < 3; i++) nvme.add(at(box(0.42, 0.05, 0.3, mat(0x15191b), 0.01), -0.6 + i * 0.55, 0.045, 0));
  at(nvme, -0.25, 0.06, 0.45); g.add(nvme);
  const chip = box(0.62, 0.09, 0.62, mat(0x0a1013, { emissive: C.alive, emissiveIntensity: 0.35 }), 0.04);
  at(chip, 0.85, 0.08, -0.4); g.add(chip); g.userData.chip = chip;
  const label = canvasTex(512, 128, (x, w, h) => { x.fillStyle = "#101A1F"; x.fillRect(0, 0, w, h); x.fillStyle = "#7FA3B0"; x.font = "600 34px monospace"; x.fillText("ML-DSA-65 · HMAC CHAIN", 18, 78); });
  const lp = new THREE.Mesh(new THREE.PlaneGeometry(1.6, 0.4), new THREE.MeshStandardMaterial({ map: label, roughness: 0.8 }));
  lp.rotation.x = -Math.PI / 2; at(lp, -0.5, 0.035, -0.45); g.add(lp);
  return g;
}
function netLayer() {
  const g = new THREE.Group();
  g.add(box(3.0, 0.06, 1.95, mat(0x121a1e), 0.05));
  for (let i = 0; i < 2; i++) {
    const port = new THREE.Group();
    port.add(box(0.62, 0.5, 0.7, mat(0xc9cfd2, { metalness: 0.85, roughness: 0.3 }), 0.03));
    port.add(at(box(0.42, 0.26, 0.2, mat(0x0a0d0f), 0.02), 0, -0.02, 0.28));
    const led = new THREE.Mesh(new THREE.SphereGeometry(0.045, 16, 12), new THREE.MeshStandardMaterial({ color: i ? C.amber : C.alive, emissive: i ? C.amber : C.alive, emissiveIntensity: 2 }));
    at(led, 0.2, 0.18, 0.36); port.add(led);
    at(port, -0.6 + i * 0.85, 0.28, 0.5); g.add(port);
  }
  for (let i = 0; i < 2; i++) {
    const curve = new THREE.CatmullRomCurve3([new THREE.Vector3(-0.6 + i * 0.85, 0.25, 0.95), new THREE.Vector3(-0.4 + i * 0.85, 0.1, 1.5), new THREE.Vector3(0.6 + i * 0.6, 0.05, 2.2)]);
    const cab = new THREE.Mesh(new THREE.TubeGeometry(curve, 40, 0.07, 12), mat(C.blue, { roughness: 0.45 })); cab.castShadow = true; g.add(cab);
  }
  return g;
}
function powerLayer() {
  const g = new THREE.Group();
  g.add(box(3.0, 0.06, 1.95, mat(0x14191c), 0.05));
  for (let i = 0; i < 3; i++) {
    const cell = new THREE.Mesh(new THREE.CylinderGeometry(0.2, 0.2, 2.2, 40), mat(0x2d3a41, { metalness: 0.3, roughness: 0.35 }));
    cell.rotation.z = Math.PI / 2; at(cell, -0.1, 0.24, -0.55 + i * 0.55); cell.castShadow = true; g.add(cell);
    const cap = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 0.08, 24), mat(0xb8c2c6, { metalness: 0.9, roughness: 0.25 }));
    cap.rotation.z = Math.PI / 2; at(cap, 1.04, 0.24, -0.55 + i * 0.55); g.add(cap);
  }
  return g;
}
function baseLayer() {
  const g = new THREE.Group();
  const top = canvasTex(1024, 680, (x, w, h) => {
    const gr = x.createLinearGradient(0, 0, w, h); gr.addColorStop(0, "#1C262B"); gr.addColorStop(1, "#0E1418"); x.fillStyle = gr; x.fillRect(0, 0, w, h);
    x.fillStyle = "#070B0D"; for (let i = 0; i < 6; i++) { x.beginPath(); x.roundRect(80, 90 + i * 40, 560, 14, 7); x.fill(); }
    mark(x, 760, 380, 1.05, "#C9D3D7");
    x.fillStyle = "#82959F"; x.font = "600 30px monospace"; x.fillText("ACRS BOX", 80, 600);
  });
  const shell = box(3.6, 0.42, 2.45, [mat(0x141c21, { roughness: 0.45, metalness: 0.35 })][0], 0.16);
  g.add(shell);
  const lid = new THREE.Mesh(new THREE.PlaneGeometry(3.3, 2.15), new THREE.MeshStandardMaterial({ map: top, roughness: 0.5, metalness: 0.3 }));
  lid.rotation.x = -Math.PI / 2; at(lid, 0, 0.215, 0); lid.receiveShadow = true; g.add(lid);
  return g;
}

export function start(opts) {
  const { stage, BX, labels, isActive } = opts;
  const probe = document.createElement("canvas");
  if (!(probe.getContext("webgl2") || probe.getContext("webgl"))) return false;
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.6));
  renderer.outputColorSpace = THREE.SRGBColorSpace; renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = 1.05;
  renderer.shadowMap.enabled = true; renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.domElement.className = "box3d-canvas"; stage.prepend(renderer.domElement);
  const scene = new THREE.Scene();
  const pm = new THREE.PMREMGenerator(renderer); scene.environment = pm.fromScene(new RoomEnvironment(), 0.04).texture;
  const cam = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
  const key = new THREE.DirectionalLight(0xffffff, 1.6); key.position.set(4, 9, 6); key.castShadow = true;
  key.shadow.mapSize.set(1024, 1024); Object.assign(key.shadow.camera, { left: -6, right: 6, top: 6, bottom: -6, near: 1, far: 30 }); scene.add(key);
  const rim = new THREE.DirectionalLight(C.alive, 0.9); rim.position.set(-6, 3, -5); scene.add(rim);
  scene.add(new THREE.HemisphereLight(0x9fb4c0, 0x050809, 0.35));
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(40, 40), new THREE.ShadowMaterial({ opacity: 0.45 }));
  floor.rotation.x = -Math.PI / 2; floor.position.y = -1.9; floor.receiveShadow = true; scene.add(floor);
  const rig = new THREE.Group(); scene.add(rig);
  const layers = [screenLayer(), piLayer(), sealLayer(), netLayer(), powerLayer(), baseLayer()];
  layers.forEach((l) => rig.add(l));
  rig.rotation.y = -0.62;

  // labels: HTML, positioned each frame from the 3D anchor of each layer
  const labBox = document.createElement("div"); labBox.className = "box3d-labels"; stage.append(labBox);
  const labEls = labels.map((L) => {
    const d = document.createElement("div"); d.className = "b3-label";
    const b = document.createElement("b"); b.textContent = L.t;
    const s = document.createElement("span"); s.textContent = L.d;
    const i = document.createElement("i"); i.className = L.ok ? "ok" : "wip"; i.textContent = L.st;
    const line = document.createElement("em");
    d.append(b, s, i, line); labBox.append(d); return d;
  });
  window.ACRSBox3D.relabel = (L2) => L2.forEach((L, i) => {
    const d = labEls[i]; d.children[0].textContent = L.t; d.children[1].textContent = L.d;
    d.children[2].textContent = L.st; d.children[2].className = L.ok ? "ok" : "wip";
  });
  const v = new THREE.Vector3();
  let up = 0, side = 0, tilt = 0, raf = 0, last = performance.now(), W = 0, H = 0;
  function size() {
    const r = stage.getBoundingClientRect(); W = r.width; H = r.height;
    renderer.setSize(W, H, false); cam.aspect = W / H; cam.updateProjectionMatrix();
  }
  size(); new ResizeObserver(size).observe(stage);
  const n = layers.length;
  function frame(now) {
    raf = requestAnimationFrame(frame);
    if (!isActive() || document.hidden) return;
    const dt = Math.min(0.05, (now - last) / 1000); last = now;
    const k = 1 - Math.pow(0.0009, dt);                     // frame-rate independent easing
    up += (BX.tu - up) * k; side += (BX.ts - side) * k; tilt += (BX.tt - tilt) * k;
    const gap = 0.26 + up * 1.05;
    layers.forEach((l, i) => {
      const c = (n - 1) / 2 - i;
      l.position.set(c * side * 2.0, c * gap, -c * side * 0.4);
      l.rotation.z = c * side * 0.05;
    });
    rig.rotation.y = -0.62 + tilt * 0.06 + Math.sin(now / 2600) * 0.04;
    rig.position.y = side * 0.4;
    const fan = layers[1].userData.fan; if (fan) fan.rotation.y += dt * 9;
    const chip = layers[2].userData.chip; if (chip) chip.material.emissiveIntensity = 0.25 + 0.2 * (0.5 + 0.5 * Math.sin(now / 420));
    const dist = 9.2 + up * 3.4 + side * 3.6;
    cam.position.set(0, 4.2 + up * 1.4, dist); cam.lookAt(0, -0.2 + up * 0.1, 0);
    renderer.render(scene, cam);
    const show = up > 0.68 && up >= side;
    labEls.forEach((d, i) => {
      v.set(-1.65, 0, 0.9); layers[i].localToWorld(v); v.project(cam);
      const x = (v.x * 0.5 + 0.5) * W, y = (-v.y * 0.5 + 0.5) * H;
      d.style.transform = `translate(${(x - 300).toFixed(0)}px, ${(y - 14).toFixed(0)}px)`;
      d.classList.toggle("is-on", show);
    });
  }
  raf = requestAnimationFrame(frame);
  return true;
}
window.ACRSBox3D = { start };
