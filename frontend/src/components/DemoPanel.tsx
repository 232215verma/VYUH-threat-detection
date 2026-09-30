import type { CSSProperties } from "react";
import { THREAT_INFO } from "../threatInfo";

const SCENARIOS: { key: string; type: string }[] = [
  { key: "portscan", type: "PortScan" },
  { key: "dga", type: "DGA" },
  { key: "dnstunnel", type: "DNSTunneling" },
  { key: "c2", type: "C2Beaconing" },
  { key: "exfil", type: "Exfiltration" },
  { key: "ddos", type: "DDoS" },
];

interface Props {
  onTriggerAttack: (key: string) => void;
  onTriggerFullDemo: () => void;
  onReplay: () => void;
  busy: boolean;
  liveMode: boolean;
  onToggleLive: () => void;
}

export default function DemoPanel({ onTriggerAttack, onTriggerFullDemo, onReplay, busy, liveMode, onToggleLive }: Props) {
  return (
    <div className="console">
      <span className="console-label">Scenario Console</span>
      {SCENARIOS.map((s) => {
        const info = THREAT_INFO[s.type];
        return (
          <button
            key={s.key}
            className="chip"
            disabled={busy}
            onClick={() => onTriggerAttack(s.key)}
            style={{ "--chip-color": info.color } as CSSProperties}
          >
            <span className="chip-dot" />
            {info.label}
          </button>
        );
      })}
      <div className="console-actions">
        <button
          className={`btn btn-ghost ${liveMode ? "btn-live-on" : ""}`}
          onClick={onToggleLive}
          title="Keep scanning continuously, one scenario after another"
        >
          <span className="live-dot" />
          {liveMode ? "Live monitoring: ON" : "Live monitoring: OFF"}
        </button>
        <button className="btn btn-ghost" disabled={busy} onClick={onReplay}>
          Replay dataset
        </button>
        <button className="btn btn-primary" disabled={busy} onClick={onTriggerFullDemo}>
          Run scripted demo
        </button>
      </div>
    </div>
  );
}