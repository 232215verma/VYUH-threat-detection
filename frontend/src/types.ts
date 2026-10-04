export interface AlertGraphNode {
  id: string;
  flagged: boolean;
  types: string[];
  primaryType: string;
}

export interface AlertGraphLink {
  source: string;
  target: string;
  type: string;
}

/** The shape (star / hub / fan-out / edge) this alert describes. Sent by the backend over the WebSocket. */
export interface AlertGraph {
  nodes: AlertGraphNode[];
  links: AlertGraphLink[];
}

export interface Alert {
  id?: number;
  type: string;
  source: string | null;
  target: string | null;
  confidence: number;
  layers_agreeing: string[];
  evidence: string[];
  created_at?: string;
  graph?: AlertGraph;
}

export interface WsMessage {
  event: "simulation_started" | "batch_processed" | "alert" | "simulation_complete" | "stage_announcement";
  alert?: Alert;
  total_flows?: number;
  batch?: number;
  flows_so_far?: number;
  total_alerts?: number;
  text?: string;
}