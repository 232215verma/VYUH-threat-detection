import { useEffect, useRef, useState } from "react";
import { Alert } from "../types";
import { THREAT_INFO, SEVERITY_META, severityOf } from "../threatInfo";

interface Props {
  type: string;
  alerts: Alert[];
  onViewAll: () => void;
}

export default function ThreatTypeMenu({ type, alerts, onViewAll }: Props) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  const matching = alerts.filter((a) => a.type === type);
  const info = THREAT_INFO[type];

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="legend-wrap" ref={wrapRef}>
      <span className={`legend-item ${matching.length > 0 ? "active" : ""}`}>
        <span className="legend-dot" style={{ background: info.color }} />
        {info.label} <b>{matching.length}</b>
      </span>
      <button
        className="kebab-btn"
        aria-label={`${info.label} options`}
        onClick={() => setOpen((v) => !v)}
      >
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
          <circle cx="12" cy="5" r="2" />
          <circle cx="12" cy="12" r="2" />
          <circle cx="12" cy="19" r="2" />
        </svg>
      </button>

      {open && (
        <div className="threat-popover">
          <div className="threat-popover-head">
            <span className="legend-dot" style={{ background: info.color }} />
            {info.label} — {matching.length} detection{matching.length === 1 ? "" : "s"}
          </div>

          {matching.length === 0 ? (
            <div className="threat-popover-empty">No detections of this type yet.</div>
          ) : (
            <div className="threat-popover-list">
              {matching.slice(0, 8).map((a, i) => {
                const sev = SEVERITY_META[severityOf(a.confidence)];
                return (
                  <div key={a.id ?? i} className="threat-popover-row">
                    <div className="r-top">
                      <span>
                        {a.source || "—"}
                        {a.target ? ` → ${a.target}` : ""}
                      </span>
                      <span style={{ color: sev.color, fontWeight: 700 }}>
                        {Math.round(a.confidence * 100)}%
                      </span>
                    </div>
                    <div className="r-conf">
                      {a.layers_agreeing.length} layer{a.layers_agreeing.length > 1 ? "s" : ""} agree · {sev.label}
                    </div>
                  </div>
                );
              })}
              {matching.length > 8 && (
                <div className="threat-popover-empty">+{matching.length - 8} more — view all for full list</div>
              )}
            </div>
          )}

          <div className="threat-popover-footer">
            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                setOpen(false);
                onViewAll();
              }}
            >
              View all in Alert Center
            </button>
          </div>
        </div>
      )}
    </div>
  );
}