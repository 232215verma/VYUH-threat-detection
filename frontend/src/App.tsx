import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AlertDrawer from "./components/AlertDrawer";
import LiveGraph, { GraphNode, GraphLink } from "./components/LiveGraph";
import ActivityChart, { ActivityPoint } from "./components/ActivityChart";
import DemoPanel from "./components/DemoPanel";
import { Alert, WsMessage } from "./types";
import { THREAT_INFO, THREAT_ORDER, severityOf } from "./threatInfo";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws/live";
const RECONNECT_DELAY_MS = 2000;

// How long detection events are kept for the live timeline
const HISTORY_KEEP_MS = 15 * 60 * 1000;

// Autonomous monitoring: a new scan starts every 30 s, and the backend is re-checked every 30 s
const LIVE_SEQUENCE = ["full", "portscan", "ddos", "dga", "dnstunnel", "c2", "exfil"];
const LIVE_INTERVAL_MS = 30_000; // a new scan starts every 30 seconds, on its own
const POLL_MS = 30_000;

// Scenario button key -> threat type (so the chart can use that scenario's own color)
const SCENARIO_TYPE: Record<string, string> = {
  portscan: "PortScan",
  dga: "DGA",
  dnstunnel: "DNSTunneling",
  c2: "C2Beaconing",
  exfil: "Exfiltration",
  ddos: "DDoS",
};

export default function App() {
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState("Idle");
  const [totalFlows, setTotalFlows] = useState<number | null>(null);
  const [flowsSoFar, setFlowsSoFar] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [history, setHistory] = useState<ActivityPoint[]>([]);
  const [stageText, setStageText] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [seenCount, setSeenCount] = useState(0);
  const [focusType, setFocusType] = useState<string | null>(null);
  const [liveMode, setLiveMode] = useState(true); // autonomous by default

  const flowsRef = useRef(0);
  const liveModeRef = useRef(true);
  const isRunningRef = useRef(false);
  const lastLaunchRef = useRef(0);
  const seqRef = useRef(0);
  const alertsRef = useRef<Alert[]>([]);
  const launchNextRef = useRef<() => void>(() => {});
  liveModeRef.current = liveMode;
  isRunningRef.current = isRunning;
  alertsRef.current = alerts;
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  const graph = useMemo(() => {
    const nodeBest = new Map<string, { types: Set<string>; primaryType: string; best: number }>();
    const linkKeys = new Set<string>();
    const links: GraphLink[] = [];

    for (const alert of alerts) {
      for (const id of [alert.source, alert.target]) {
        if (!id) continue;
        const existing = nodeBest.get(id);
        if (!existing) {
          nodeBest.set(id, { types: new Set([alert.type]), primaryType: alert.type, best: alert.confidence });
        } else {
          existing.types.add(alert.type);
          if (alert.confidence > existing.best) {
            existing.primaryType = alert.type;
            existing.best = alert.confidence;
          }
        }
      }
      if (alert.source && alert.target) {
        const key = `${alert.source}->${alert.target}->${alert.type}`;
        if (!linkKeys.has(key)) {
          linkKeys.add(key);
          links.push({ source: alert.source, target: alert.target, type: alert.type });
        }
      }
    }

    const nodes: GraphNode[] = Array.from(nodeBest.entries()).map(([id, d]) => ({
      id,
      flagged: true,
      types: Array.from(d.types),
      primaryType: d.primaryType,
    }));
    return { nodes, links };
  }, [alerts]);

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of alerts) counts[a.type] = (counts[a.type] || 0) + 1;
    return counts;
  }, [alerts]);

  const criticalCount = useMemo(
    () => alerts.filter((a) => severityOf(a.confidence) === "critical").length,
    [alerts]
  );

  const pushHistoryPoint = useCallback((alertType: string) => {
    const now = Date.now();
    setHistory((prev) => [...prev.filter((p) => now - p.t < HISTORY_KEEP_MS), { t: now, type: alertType }]);
  }, []);

  // Keep the "new alerts" indicator in sync while the drawer is open.
  useEffect(() => {
    if (drawerOpen) setSeenCount(alerts.length);
  }, [drawerOpen, alerts.length]);

  useEffect(() => {
    fetch(`${API_BASE}/api/alerts`)
      .then((res) => {
        if (!res.ok) throw new Error();
        return res.json();
      })
      .then((data: { alerts: Alert[] }) => {
        setAlerts(data.alerts);
        setSeenCount(data.alerts.length);
      })
      .catch(() => setErrorBanner("Unable to load alert history. Verify that the backend is running on port 8000."));
  }, []);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setErrorBanner(null);
      };
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) reconnectTimerRef.current = window.setTimeout(connect, RECONNECT_DELAY_MS);
      };
      ws.onerror = () => setConnected(false);

      ws.onmessage = (event) => {
        const msg: WsMessage = JSON.parse(event.data);
        switch (msg.event) {
          case "stage_announcement":
            setStageText(msg.text ?? null);
            break;
          case "simulation_started":
            setStatus(`Analyzing ${msg.total_flows?.toLocaleString()} flows`);
            setTotalFlows(msg.total_flows ?? null);
            setIsComplete(false);
            setIsRunning(true);
            break;
          case "batch_processed":
            flowsRef.current = msg.flows_so_far ?? 0;
            setFlowsSoFar(flowsRef.current);
            setStatus(`Analyzed ${flowsRef.current.toLocaleString()} flows`);
            break;
          case "alert":
            if (msg.alert) {
              setAlerts((prev) => [msg.alert!, ...prev]);
              pushHistoryPoint(msg.alert.type);
            }
            break;
          case "simulation_complete":
            setStatus(`Run complete · ${msg.total_alerts} unique detections`);
            setIsComplete(true);
            setIsRunning(false);
            break;
        }
      };
    }

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [pushHistoryPoint]);

  const resetForNewRun = () => {
    lastLaunchRef.current = Date.now();
    setIsComplete(false);
    setStageText(null);
    flowsRef.current = 0;
    setFlowsSoFar(0);
  };

  const post = async (path: string, body?: unknown) => {
    const res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    if (!res.ok) throw new Error();
  };

  const startSimulation = async () => {
    resetForNewRun();
    setFocusType(null);
    setStatus("Starting dataset replay…");
    setErrorBanner(null);
    try {
      await post("/api/start-simulation");
    } catch {
      setErrorBanner("Unable to start the replay. Verify that the backend is running.");
      setStatus("Idle");
    }
  };

  const triggerAttack = async (attack: string) => {
    resetForNewRun();
    setFocusType(liveModeRef.current ? null : SCENARIO_TYPE[attack] ?? null);
    setStatus("Launching scenario…");
    setErrorBanner(null);
    try {
      await post("/api/demo/attack", { attack });
    } catch {
      setErrorBanner("Unable to launch the scenario. Verify that the backend is running.");
      setStatus("Idle");
    }
  };

  const triggerFullDemo = async () => {
    resetForNewRun();
    setFocusType(null);
    setStatus("Running scripted demo…");
    setErrorBanner(null);
    try {
      await post("/api/demo/full");
    } catch {
      setErrorBanner("Unable to start the scripted demo. Verify that the backend is running.");
      setStatus("Idle");
    }
  };

  const clearAll = async () => {
    try {
      await fetch(`${API_BASE}/api/alerts`, { method: "DELETE" });
    } catch {
      setErrorBanner("Unable to reach the backend to clear alerts.");
    }
    setHistory([]);
    setFocusType(null);
    setAlerts([]);
    setSeenCount(0);
    setTotalFlows(null);
    setStatus("Cleared");
    resetForNewRun();
  };

  const toggleLive = () => {
    lastLaunchRef.current = 0; // start the first scan right away
    setLiveMode((v) => !v);
  };

  // Always points at the latest trigger functions, so the timer below never uses stale ones.
  launchNextRef.current = () => {
    const step = LIVE_SEQUENCE[seqRef.current % LIVE_SEQUENCE.length];
    seqRef.current += 1;
    if (step === "full") void triggerFullDemo();
    else void triggerAttack(step);
  };

  // Autonomous monitoring: start a scan every 30 s (or right after the previous one ends if it ran longer), forever.
  useEffect(() => {
    if (!liveMode || !connected) return;
    const id = window.setInterval(() => {
      if (isRunningRef.current) return;
      if (Date.now() - lastLaunchRef.current < LIVE_INTERVAL_MS) return;
      launchNextRef.current();
    }, 1000);
    return () => clearInterval(id);
  }, [liveMode, connected]);

  // Every 30 s, pull alerts the backend has that this page has not seen yet (needs alerts to carry an id).
  useEffect(() => {
    const id = window.setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/alerts`);
        if (!res.ok) return;
        const data: { alerts: Alert[] } = await res.json();
        const known = new Set<unknown>(alertsRef.current.map((a) => a.id).filter((x) => x != null));
        const fresh = data.alerts.filter((a) => a.id != null && !known.has(a.id));
        if (fresh.length === 0) return;
        setAlerts((prev) => [...fresh, ...prev]);
        fresh.forEach((a) => pushHistoryPoint(a.type));
      } catch {
        /* backend unreachable, try again on the next tick */
      }
    }, POLL_MS);
    return () => clearInterval(id);
  }, [pushHistoryPoint]);

  const unseen = Math.max(0, alerts.length - seenCount);
  const categories = Object.keys(typeCounts).length;

  return (
    <div className="app">
      {errorBanner && <div className="error-banner">{errorBanner}</div>}

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round">
              <circle cx="5" cy="6" r="2.2" />
              <circle cx="19" cy="7" r="2.2" />
              <circle cx="12" cy="18" r="2.2" />
              <path d="M7 6.6l10 .4M6.4 8l4.6 8.2M17.8 8.9l-4.6 7.3" />
            </svg>
          </div>
          <div>
            <div className="brand-name">NetGraph Sentinel</div>
            <div className="brand-sub">Graph-based passive threat detection</div>
          </div>
        </div>

        <div className="conn">
          <span className={`conn-dot ${connected ? "on" : ""}`} />
          {connected ? "Connected" : "Reconnecting…"}
        </div>

        <div className="topbar-status">
          {isRunning && <span className="spinner" />}
          {status}
        </div>

        <button className="btn btn-ghost" onClick={clearAll}>
          Clear
        </button>
        <button className="btn btn-alert" onClick={() => setDrawerOpen(true)}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
            <path d="M13.7 21a2 2 0 01-3.4 0" />
          </svg>
          Alert Center
          <span className={`count-badge ${unseen > 0 ? "new" : ""}`}>{alerts.length}</span>
        </button>
      </header>

      <DemoPanel
        onTriggerAttack={triggerAttack}
        onTriggerFullDemo={triggerFullDemo}
        onReplay={startSimulation}
        busy={isRunning}
        liveMode={liveMode}
        onToggleLive={toggleLive}
      />

      {stageText && <div className="stage-banner">{stageText.replace(/^[^A-Za-z0-9]+/, "")}</div>}

      <section className="kpis">
        <div className="kpi" style={{ ["--kpi-color" as string]: "#38bdf8" }}>
          <div className="kpi-label">Total alerts</div>
          <div className="kpi-value">{alerts.length}</div>
          <div className="kpi-sub">
            {categories} threat {categories === 1 ? "category" : "categories"}
          </div>
        </div>
        <div className="kpi" style={{ ["--kpi-color" as string]: "#f43f5e" }}>
          <div className="kpi-label">Critical</div>
          <div className="kpi-value">{criticalCount}</div>
          <div className="kpi-sub">Confidence ≥ 90%</div>
        </div>
        <div className="kpi" style={{ ["--kpi-color" as string]: "#a78bfa" }}>
          <div className="kpi-label">Hosts flagged</div>
          <div className="kpi-value">{graph.nodes.length}</div>
          <div className="kpi-sub">Distinct IP addresses</div>
        </div>
        <div className="kpi" style={{ ["--kpi-color" as string]: "#34d399" }}>
          <div className="kpi-label">Flows analyzed</div>
          <div className="kpi-value">{flowsSoFar.toLocaleString()}</div>
          <div className="kpi-sub">
            {totalFlows ? `of ${totalFlows.toLocaleString()} in this run` : "No run in progress"}
          </div>
        </div>
      </section>

      <section className="activity-section">
        <div className="stage-head">
          <div>
            <div className="stage-title">Detection activity</div>
            <div className="stage-sub">Live timeline of detections, moving continuously with a marker every 30 seconds. A single scenario shows its own color, a full scan shows one wave per threat type</div>
          </div>
        </div>
        <div className="activity-body">
          <ActivityChart data={history} height={320} focusType={focusType} totalAlerts={alerts.length} />
        </div>
      </section>

      <section className="stage">
        <div className="stage-head">
          <div>
            <div className="stage-title">Network topology</div>
            <div className="stage-sub">Hosts and connections implicated in detected threats</div>
          </div>
          <div className="legend">
            {THREAT_ORDER.map((type) => {
              const info = THREAT_INFO[type];
              const count = typeCounts[type] || 0;
              return (
                <span key={type} className={`legend-item ${count > 0 ? "active" : ""}`}>
                  <span className="legend-dot" style={{ background: info.color }} />
                  {info.label} <b>{count}</b>
                </span>
              );
            })}
          </div>
        </div>

        <LiveGraph nodes={graph.nodes} links={graph.links}>
          {graph.nodes.length === 0 && (
            <div className="empty">
              <div className="empty-title">No activity yet</div>
              <div className="empty-text">
                Launch a scenario from the console above, or replay the dataset, to see the network topology build in real time.
              </div>
            </div>
          )}
        </LiveGraph>
      </section>

      <AlertDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        alerts={alerts}
        isComplete={isComplete}
        totalFlows={totalFlows}
        flaggedIpCount={graph.nodes.length}
      />
    </div>
  );
}