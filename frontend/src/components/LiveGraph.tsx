import ForceGraph2D from "react-force-graph-2d";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { THREAT_INFO } from "../threatInfo";

export interface GraphNode {
  id: string;
  flagged: boolean;
  types: string[];
  primaryType: string;
  /** The middle of the shape (scanner of a star, target of a hub). Drawn bigger and always labelled. */
  center?: boolean;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
}

interface Props {
  nodes: GraphNode[];
  links: GraphLink[];
  children?: ReactNode;
}

// Small graphs: label every node. Big graphs: label only the centre, and the rest once zoomed in.
const LABEL_ALL_MAX_NODES = 8;
const LABEL_ZOOM = 2.2;

export default function LiveGraph({ nodes, links, children }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<any>(null);
  const cacheRef = useRef<Map<string, any>>(new Map());
  const [size, setSize] = useState({ w: 0, h: 0 });

  // Size the canvas to its container (not the window) so nothing is cut off.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const update = () => setSize({ w: el.clientWidth, h: el.clientHeight });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Reuse node objects between updates so positions stay stable as alerts arrive.
  const graphData = useMemo(() => {
    const cache = cacheRef.current;
    const liveIds = new Set(nodes.map((n) => n.id));
    for (const id of Array.from(cache.keys())) {
      if (!liveIds.has(id)) cache.delete(id);
    }
    const outNodes = nodes.map((n) => {
      const existing = cache.get(n.id);
      if (existing) {
        Object.assign(existing, n);
        return existing;
      }
      const fresh = { ...n };
      cache.set(n.id, fresh);
      return fresh;
    });
    const outLinks = links.map((l) => ({ source: l.source, target: l.target, type: l.type }));
    return { nodes: outNodes, links: outLinks };
  }, [nodes, links]);

  const fit = useCallback(() => {
    fgRef.current?.zoomToFit(400, 70);
  }, []);

  // A new shape replaced the old one: re-frame the view once it settles.
  useEffect(() => {
    if (nodes.length === 0) return;
    const t = window.setTimeout(fit, 700);
    return () => clearTimeout(t);
  }, [nodes.length, fit]);

  const labelAll = nodes.length <= LABEL_ALL_MAX_NODES;

  const drawNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, scale: number) => {
      const color = THREAT_INFO[node.primaryType]?.color || "#e8a33c";
      const isCenter = !!node.center;
      const r = (isCenter ? 9 : 4) / scale;

      ctx.beginPath();
      ctx.arc(node.x, node.y, r * 2.1, 0, 2 * Math.PI);
      ctx.fillStyle = `${color}${isCenter ? "33" : "22"}`;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = "#0e131e";
      ctx.lineWidth = 1.2 / scale;
      ctx.stroke();

      if (isCenter || labelAll || scale > LABEL_ZOOM) {
        ctx.font = `${(isCenter ? 12 : 10.5) / scale}px 'JetBrains Mono', monospace`;
        ctx.fillStyle = isCenter ? "#e6ebf5" : "#98a4b9";
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(node.id, node.x + r + 4 / scale, node.y);
      }
    },
    [labelAll]
  );

  return (
    <div ref={wrapRef} className="canvas-wrap">
      {size.w > 0 && size.h > 0 && (
        <ForceGraph2D
          ref={fgRef}
          width={size.w}
          height={size.h}
          graphData={graphData as any}
          backgroundColor="rgba(0,0,0,0)"
          nodeLabel={(node: any) => {
            const names = (node.types || []).map((t: string) => THREAT_INFO[t]?.label || t);
            return `${node.id} — ${names.join(", ")}`;
          }}
          nodeCanvasObject={drawNode}
          nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.center ? 12 : 8, 0, 2 * Math.PI);
            ctx.fill();
          }}
          linkColor={(link: any) => `${THREAT_INFO[link.type]?.color || "#64718a"}aa`}
          linkWidth={1.4}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={(link: any) => THREAT_INFO[link.type]?.color || "#fff"}
          cooldownTicks={150}
          onEngineStop={fit}
        />
      )}
      <div className="graph-controls">
        <button className="mini-btn" onClick={fit}>
          Fit to view
        </button>
      </div>
      {children}
    </div>
  );
}