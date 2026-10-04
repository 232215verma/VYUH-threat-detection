import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import * as THREE from "three";
import { THREAT_INFO, THREAT_ORDER } from "../threatInfo";

/** One detection event on the live timeline. */
export interface ActivityPoint {
  t: number; // Date.now() when the alert arrived
  type: string;
}

interface Props {
  data: ActivityPoint[];
  height?: number;
  /** When a single scenario is running, only that threat type (in its own color) is drawn. */
  focusType?: string | null;
  totalAlerts?: number;
}

/* ---------- Tuning knobs ---------- */
const WINDOW_MS = 4 * 60_000; // length of the visible timeline
const FUTURE_MS = 8_000; // headroom right of "now" so a fresh wave is not cut in half
const TICK_MS = 30_000; // one marker on the timeline every 30 seconds
const SIGMA_MS = 3_500; // width of the bell each detection makes (bigger = wider, softer waves)
const RISE_MS = 900; // new detections rise smoothly instead of popping in
const RIPPLE = 0.09; // strength of the flowing ripple travelling along the waves
const SAMPLES = 260; // points per wave

const M = { top: 12, right: 14, bottom: 34, left: 46 };
const FALLBACK_COLOR = "#e8a33c";
const IDLE = "__idle__";

/* ---------- Helpers ---------- */
const colorOf = (t: string) => THREAT_INFO[t]?.color || FALLBACK_COLOR;

function hexToVec3(hex: string): THREE.Vector3 {
  const h = hex.replace("#", "");
  const n = parseInt(h.length === 3 ? h.split("").map((c) => c + c).join("") : h, 16);
  return new THREE.Vector3(((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255);
}

function phaseOf(type: string): number {
  let s = 0;
  for (let i = 0; i < type.length; i++) s += type.charCodeAt(i) * (i + 1);
  return (s % 628) / 100;
}

const easeOut = (x: number) => 1 - Math.pow(1 - Math.min(1, Math.max(0, x)), 3);
const ripple = (x: number, time: number, phase: number) => 1 + RIPPLE * Math.sin(x * 0.05 - time * 2.4 + phase);

const fmtTime = (t: number) =>
  new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

function pickTypes(events: ActivityPoint[], focus: string | null | undefined, tStart: number): string[] {
  if (focus) return [focus];
  const present = new Set<string>();
  for (const e of events) if (e.t >= tStart - 3 * SIGMA_MS) present.add(e.type);
  return [
    ...THREAT_ORDER.filter((t) => present.has(t)),
    ...Array.from(present).filter((t) => !THREAT_ORDER.includes(t)),
  ];
}

/** Every detection adds a soft bell; overlapping bells merge into rolling waves. */
function buildCurves(
  events: ActivityPoint[],
  typeKeys: string[],
  tStart: number,
  tEnd: number,
  nowMs: number
): Record<string, Float32Array> {
  const dt = (tEnd - tStart) / (SAMPLES - 1);
  const out: Record<string, Float32Array> = {};
  for (const t of typeKeys) out[t] = new Float32Array(SAMPLES);
  const R = 3 * SIGMA_MS;
  for (const e of events) {
    const arr = out[e.type];
    if (!arr) continue;
    if (e.t < tStart - R || e.t > tEnd + R) continue;
    const w = easeOut((nowMs - e.t) / RISE_MS);
    if (w <= 0) continue;
    const lo = Math.max(0, Math.ceil((e.t - R - tStart) / dt));
    const hi = Math.min(SAMPLES - 1, Math.floor((e.t + R - tStart) / dt));
    for (let j = lo; j <= hi; j++) {
      const d = (tStart + j * dt - e.t) / SIGMA_MS;
      arr[j] += w * Math.exp(-0.5 * d * d);
    }
  }
  return out;
}

function valueAt(events: ActivityPoint[], type: string, t: number, nowMs: number): number {
  let v = 0;
  for (const e of events) {
    if (e.type !== type) continue;
    const d = (t - e.t) / SIGMA_MS;
    if (Math.abs(d) > 3) continue;
    v += easeOut((nowMs - e.t) / RISE_MS) * Math.exp(-0.5 * d * d);
  }
  return v;
}

/* ---------- three.js pieces (kept deliberately small) ---------- */
const VERT = `
attribute float aFade;
varying float vFade;
void main() {
  vFade = aFade;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`;
const FRAG = `
uniform vec3 uColor;
uniform float uAlpha;
varying float vFade;
void main() {
  gl_FragColor = vec4(uColor, uAlpha * vFade);
}`;

interface Layer {
  geo: THREE.BufferGeometry;
  pos: Float32Array;
  attr: THREE.BufferAttribute;
  mat: THREE.ShaderMaterial;
  mesh: THREE.Mesh;
}

interface Wave {
  group: THREE.Group;
  area: Layer | null;
  glow: Layer;
  core: Layer;
  alpha: number;
  ys: Float32Array;
  phase: number;
}

function makeLayer(color: THREE.Vector3, isArea: boolean, order: number): Layer {
  const pos = new Float32Array(SAMPLES * 2 * 3);
  const fade = new Float32Array(SAMPLES * 2);
  for (let j = 0; j < SAMPLES; j++) {
    fade[2 * j] = 1;
    fade[2 * j + 1] = isArea ? 0 : 1;
  }
  const idx: number[] = [];
  for (let j = 0; j < SAMPLES - 1; j++) {
    const a = 2 * j;
    idx.push(a, a + 1, a + 2, a + 1, a + 3, a + 2);
  }
  const geo = new THREE.BufferGeometry();
  const attr = new THREE.BufferAttribute(pos, 3);
  attr.setUsage(THREE.DynamicDrawUsage);
  geo.setAttribute("position", attr);
  geo.setAttribute("aFade", new THREE.BufferAttribute(fade, 1));
  geo.setIndex(idx);
  const mat = new THREE.ShaderMaterial({
    uniforms: { uColor: { value: color }, uAlpha: { value: 0 } },
    vertexShader: VERT,
    fragmentShader: FRAG,
    transparent: true,
    depthTest: false,
    depthWrite: false,
    side: THREE.DoubleSide,
  });
  const mesh = new THREE.Mesh(geo, mat);
  mesh.frustumCulled = false;
  mesh.renderOrder = order;
  return { geo, pos, attr, mat, mesh };
}

function writeRibbon(layer: Layer, xs: Float32Array, ys: Float32Array, half: number) {
  const n = xs.length;
  const pos = layer.pos;
  for (let j = 0; j < n; j++) {
    const j0 = Math.max(0, j - 1);
    const j1 = Math.min(n - 1, j + 1);
    const dx = xs[j1] - xs[j0];
    const dy = ys[j1] - ys[j0];
    const len = Math.hypot(dx, dy) || 1;
    const nx = -dy / len;
    const ny = dx / len;
    const o = j * 6;
    pos[o] = xs[j] + nx * half;
    pos[o + 1] = ys[j] + ny * half;
    pos[o + 2] = 0;
    pos[o + 3] = xs[j] - nx * half;
    pos[o + 4] = ys[j] - ny * half;
    pos[o + 5] = 0;
  }
  layer.attr.needsUpdate = true;
}

function writeArea(layer: Layer, xs: Float32Array, ys: Float32Array, baseY: number) {
  const pos = layer.pos;
  for (let j = 0; j < xs.length; j++) {
    const o = j * 6;
    pos[o] = xs[j];
    pos[o + 1] = ys[j];
    pos[o + 2] = 0;
    pos[o + 3] = xs[j];
    pos[o + 4] = baseY;
    pos[o + 5] = 0;
  }
  layer.attr.needsUpdate = true;
}

function disposeWave(w: Wave) {
  for (const l of [w.area, w.glow, w.core]) {
    if (!l) continue;
    l.geo.dispose();
    l.mat.dispose();
  }
}

/* ---------- Component ---------- */
export default function ActivityChart({ data, height = 140, focusType = null, totalAlerts }: Props) {
  const plotRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const cameraRef = useRef<THREE.OrthographicCamera | null>(null);
  const sizeRef = useRef({ w: 0, h: height });
  const dataRef = useRef(data);
  const focusRef = useRef(focusType);
  const yDispRef = useRef(4);

  dataRef.current = data;
  focusRef.current = focusType;

  const [width, setWidth] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [hoverX, setHoverX] = useState<number | null>(null);
  const [noGL, setNoGL] = useState(false);

  // Fit the chart to its container so labels never get cut off.
  useEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const update = () => setWidth(el.clientWidth);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // three.js scene + render loop (created once).
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    } catch {
      setNoGL(true);
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x000000, 0);
    const scene = new THREE.Scene();
    // Pixel coordinates, y pointing down (top = 0).
    const camera = new THREE.OrthographicCamera(0, 1, 0, 1, -10, 10);
    rendererRef.current = renderer;
    cameraRef.current = camera;

    const waves = new Map<string, Wave>();
    const xs = new Float32Array(SAMPLES);

    const getWave = (type: string): Wave => {
      let w = waves.get(type);
      if (w) return w;
      const color = hexToVec3(type === IDLE ? FALLBACK_COLOR : colorOf(type));
      const group = new THREE.Group();
      const area = type === IDLE ? null : makeLayer(color, true, 1);
      const glow = makeLayer(color, false, 2);
      const core = makeLayer(color, false, 3);
      if (area) group.add(area.mesh);
      group.add(glow.mesh);
      group.add(core.mesh);
      scene.add(group);
      w = { group, area, glow, core, alpha: 0, ys: new Float32Array(SAMPLES), phase: phaseOf(type) };
      waves.set(type, w);
      return w;
    };

    let raf = 0;
    let frame = 0;
    let visible = true;
    const io = new IntersectionObserver((entries) => {
      visible = entries[0]?.isIntersecting ?? true;
    });
    io.observe(canvas);

    const loop = () => {
      raf = requestAnimationFrame(loop);
      const { w, h } = sizeRef.current;
      if (w <= 0 || !visible) return;

      const nowMs = Date.now();
      const iw = Math.max(1, w - M.left - M.right);
      const ih = Math.max(1, h - M.top - M.bottom);
      const baseY = M.top + ih;
      const tEnd = nowMs + FUTURE_MS;
      const tStart = tEnd - WINDOW_MS;
      const events = dataRef.current;
      const typeKeys = pickTypes(events, focusRef.current, tStart);
      const curves = buildCurves(events, typeKeys, tStart, tEnd, nowMs);

      let peak = 0;
      for (const t of typeKeys) {
        const a = curves[t];
        for (let j = 0; j < SAMPLES; j++) if (a[j] > peak) peak = a[j];
      }
      const target = peak <= 1.7 ? 2 : Math.max(4, Math.ceil((peak * 1.15) / 4) * 4);
      yDispRef.current += (target - yDispRef.current) * 0.06; // eased, so the scale glides instead of jumping
      const yMax = yDispRef.current;
      const time = nowMs / 1000;

      for (let j = 0; j < SAMPLES; j++) xs[j] = M.left + (j / (SAMPLES - 1)) * iw;

      for (const t of typeKeys) getWave(t);
      getWave(IDLE);

      waves.forEach((wv, type) => {
        const isIdle = type === IDLE;
        const active = isIdle ? peak < 0.05 : typeKeys.includes(type);
        wv.alpha += ((active ? 1 : 0) - wv.alpha) * 0.12; // fade in / out smoothly
        if (wv.alpha < 0.01) {
          wv.group.visible = false;
          return;
        }
        wv.group.visible = true;

        if (active) {
          const arr = isIdle ? null : curves[type];
          for (let j = 0; j < SAMPLES; j++) {
            if (isIdle || !arr) {
              wv.ys[j] = baseY - 2.5 - 2 * Math.sin(xs[j] * 0.04 - time * 3); // resting "heartbeat" line
            } else {
              const r = arr[j] * ripple(xs[j], time, wv.phase);
              wv.ys[j] = baseY - Math.min(1.03, r / yMax) * ih;
            }
          }
          if (wv.area) writeArea(wv.area, xs, wv.ys, baseY);
          writeRibbon(wv.glow, xs, wv.ys, 4.5);
          writeRibbon(wv.core, xs, wv.ys, 1.4);
        }

        if (wv.area) wv.area.mat.uniforms.uAlpha.value = 0.34 * wv.alpha;
        wv.glow.mat.uniforms.uAlpha.value = (isIdle ? 0.08 : 0.16) * wv.alpha;
        wv.core.mat.uniforms.uAlpha.value = (isIdle ? 0.5 : 0.95) * wv.alpha;
      });

      renderer.render(scene, camera);

      frame++;
      if (frame % 2 === 0) setNow(nowMs); // labels / axes refresh at ~30fps, plenty for slow scrolling
    };
    raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
      waves.forEach(disposeWave);
      renderer.dispose();
      rendererRef.current = null;
      cameraRef.current = null;
    };
  }, []);

  // Keep the WebGL canvas the same size as the chart.
  useEffect(() => {
    sizeRef.current = { w: width, h: height };
    const r = rendererRef.current;
    const c = cameraRef.current;
    if (r && c && width > 0) {
      r.setSize(width, height);
      c.right = width;
      c.bottom = height;
      c.updateProjectionMatrix();
    }
  }, [width, height]);

  /* ----- Everything below is the SVG overlay: axes, labels, hover ----- */
  const nowMs = now;
  const iw = Math.max(0, width - M.left - M.right);
  const ih = height - M.top - M.bottom;
  const tEnd = nowMs + FUTURE_MS;
  const tStart = tEnd - WINDOW_MS;
  const xAt = (t: number) => M.left + ((t - tStart) / WINDOW_MS) * iw;
  const baseY = M.top + ih;
  const yMax = yDispRef.current;

  const typeKeys = pickTypes(data, focusType, tStart);
  const totals: Record<string, number> = {};
  let hasEvents = false;
  for (const e of data) {
    if (e.t >= tStart && typeKeys.includes(e.type)) {
      totals[e.type] = (totals[e.type] || 0) + 1;
      hasEvents = true;
    }
  }

  const yTicks = Array.from({ length: 5 }, (_, i) => ({
    y: baseY - (i / 4) * ih,
    label: (() => {
      const v = (yMax * i) / 4;
      return v >= 10 ? String(Math.round(v)) : String(Math.round(v * 10) / 10);
    })(),
  }));

  // A marker every 30 s; thin out labels on narrow screens.
  const pxPerTick = (TICK_MS / WINDOW_MS) * iw;
  const labelEvery = Math.max(1, Math.ceil(70 / Math.max(1, pxPerTick)));
  const timeTicks: { x: number; label: string | null }[] = [];
  for (let t = Math.ceil(tStart / TICK_MS) * TICK_MS; t <= tEnd; t += TICK_MS) {
    const x = xAt(t);
    if (x < M.left || x > M.left + iw) continue;
    const showLabel = (t / TICK_MS) % labelEvery === 0 && x > M.left + 26 && x < M.left + iw - 26;
    timeTicks.push({ x, label: showLabel ? fmtTime(t) : null });
  }

  const nowX = xAt(nowMs);

  const onMove = (e: ReactMouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setHoverX(e.clientX - rect.left);
  };

  const hoverOk = hoverX !== null && hoverX >= M.left && hoverX <= M.left + iw && iw > 0;
  const th = hoverOk ? tStart + (((hoverX as number) - M.left) / iw) * WINDOW_MS : 0;
  const hoverRows = hoverOk
    ? typeKeys
        .map((t) => ({
          t,
          n: data.filter((e) => e.type === t && Math.abs(e.t - th) <= 4000).length,
          v: valueAt(data, t, th, nowMs),
          color: colorOf(t),
        }))
        .filter((r) => r.n > 0)
        .sort((a, b) => b.n - a.n)
    : [];
  const hoverTotal = hoverRows.reduce((s, r) => s + r.n, 0);
  const tipW = 158;
  const tipH = 44 + Math.max(1, hoverRows.length) * 14;
  const tipX = hoverOk
    ? Math.min(Math.max((hoverX as number) - tipW / 2, M.left), Math.max(M.left, width - M.right - tipW))
    : 0;

  const focusLabel = focusType ? THREAT_INFO[focusType]?.label ?? focusType : null;

  return (
    <div className="activity">
      <div className="activity-head">
        <div className="activity-now">
          <span className="activity-now-num">{totalAlerts ?? data.length}</span>
          alerts found so far
          <span className="activity-live">
            <span className="activity-live-dot" />
            Live
          </span>
        </div>
        <div className="activity-hint">
          {focusLabel
            ? `${focusLabel} scenario: wave drawn in its own color`
            : "Autonomous: a new scan runs every 30 seconds"}
        </div>
      </div>

      <div ref={plotRef} className="activity-plot" style={{ height }}>
        <canvas ref={canvasRef} className="activity-canvas" />

        {width > 0 && (
          <svg
            className="activity-svg"
            width={width}
            height={height}
            onMouseMove={onMove}
            onMouseLeave={() => setHoverX(null)}
          >
            {/* Horizontal grid + Y labels */}
            {yTicks.map((t, i) => (
              <g key={`y${i}`}>
                <line className="activity-grid" x1={M.left} x2={M.left + iw} y1={t.y} y2={t.y} />
                <text className="activity-tick" x={M.left - 8} y={t.y + 3.5} textAnchor="end">
                  {t.label}
                </text>
              </g>
            ))}

            {/* 30-second markers, scrolling with time */}
            {timeTicks.map((t, i) => (
              <g key={`x${i}`}>
                <line className="activity-grid" x1={t.x} x2={t.x} y1={M.top} y2={baseY} strokeOpacity={0.5} />
                {t.label && (
                  <text className="activity-tick" x={t.x} y={baseY + 15} textAnchor="middle">
                    {t.label}
                  </text>
                )}
              </g>
            ))}

            {/* Axis titles */}
            <text className="activity-title" x={M.left + iw / 2} y={height - 4} textAnchor="middle">
              Time (live, marker every 30 s)  →
            </text>
            <text
              className="activity-title"
              transform={`translate(11 ${M.top + ih / 2}) rotate(-90)`}
              textAnchor="middle"
            >
              Detections
            </text>

            {/* Baseline */}
            <line className="activity-axis" x1={M.left} x2={M.left + iw} y1={baseY} y2={baseY} />

            {/* "Now" marker */}
            {nowX > M.left && nowX < M.left + iw && (
              <g pointerEvents="none">
                <line className="activity-now-line" x1={nowX} x2={nowX} y1={M.top} y2={baseY} />
                <circle className="activity-now-dot" cx={nowX} cy={baseY} r={3.5} />
                <text className="activity-tick" x={nowX - 5} y={M.top + 9} textAnchor="end" style={{ fill: "var(--accent)" }}>
                  NOW
                </text>
              </g>
            )}

            {hoverOk && (
              <g pointerEvents="none">
                <line className="activity-hover-line" x1={hoverX as number} x2={hoverX as number} y1={M.top} y2={baseY} />
                {hoverRows.map((r) => (
                  <circle
                    key={r.t}
                    className="activity-dot"
                    cx={hoverX as number}
                    cy={baseY - Math.min(1.03, (r.v * ripple(hoverX as number, nowMs / 1000, phaseOf(r.t))) / yMax) * ih}
                    r={4}
                    style={{ fill: r.color }}
                  />
                ))}
                <rect className="activity-tip-bg" x={tipX} y={M.top + 14} width={tipW} height={tipH} rx={6} />
                <text className="activity-tip-text" x={tipX + 9} y={M.top + 30}>
                  {hoverTotal} {hoverTotal === 1 ? "detection" : "detections"} here
                </text>
                <text className="activity-tip-sub" x={tipX + 9} y={M.top + 43}>
                  {fmtTime(th)}
                </text>
                {hoverRows.length === 0 && (
                  <text className="activity-tip-row" x={tipX + 9} y={M.top + 59} fill="var(--text-3)">
                    No threats at this moment
                  </text>
                )}
                {hoverRows.map((r, i) => (
                  <text key={r.t} className="activity-tip-row" x={tipX + 9} y={M.top + 59 + i * 14} fill={r.color}>
                    {(THREAT_INFO[r.t]?.label ?? r.t) + ": " + r.n}
                  </text>
                ))}
              </g>
            )}
          </svg>
        )}

        {!hasEvents && width > 0 && (
          <div className="activity-empty" style={{ top: M.top, left: M.left, right: M.right, height: ih - 20 }}>
            <div className="activity-empty-title">{noGL ? "WebGL is not available" : "Listening for threats…"}</div>
            <div className="activity-empty-text">
              {noGL
                ? "Your browser could not start WebGL, so the wave view is off."
                : "Run a scenario above. Waves rise here live as threats are detected."}
            </div>
          </div>
        )}
      </div>

      {typeKeys.length > 0 && hasEvents && (
        <div className="activity-legend">
          {typeKeys.map((t) => (
            <span key={t} className="activity-legend-item">
              <span className="activity-legend-dot" style={{ background: colorOf(t) }} />
              {THREAT_INFO[t]?.label ?? t} <b>{totals[t] || 0}</b>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}