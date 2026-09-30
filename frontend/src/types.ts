export interface Alert {
  id?: number;
  type: string;
  source: string | null;
  target: string | null;
  confidence: number;
  layers_agreeing: string[];
  evidence: string[];
  created_at?: string;
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