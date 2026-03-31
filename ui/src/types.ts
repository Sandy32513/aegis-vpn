export interface DaemonStatus {
  connected: boolean;
  server: string | null;
  session_id: number | null;
  active_circuit: string | null;
  rotation_state: string | null;
  mode: string | null;
  last_error: string | null;
  last_transition_at: string | null;
}

export interface DaemonMetrics {
  mode: string;
  uptime_secs: number;
  last_connect_latency_ms: number | null;
  packets_tx: number;
  packets_rx: number;
  request_count: number;
  error_count: number;
  error_rate: number;
  connect_count: number;
  disconnect_count: number;
  last_transition_at: string | null;
}

export interface DaemonStatusResponse {
  ok: boolean;
  kind: "status";
  status: DaemonStatus;
}

export interface DaemonMetricsResponse {
  ok: boolean;
  kind: "metrics";
  metrics: DaemonMetrics;
}

export interface ActionResponse {
  ok: boolean;
  kind: "ok";
  message: string;
}

export interface LogEntry {
  timestamp?: string;
  ts?: string;
  level?: string;
  subsystem?: string;
  component?: string;
  action?: string;
  event?: string;
  message?: string;
  raw: string;
}

export interface LogsResponse {
  ok: boolean;
  entries: LogEntry[];
}

export interface StitchScreen {
  name: string;
  id: string;
  slug: string;
  category: string;
  urlEnvVar: string;
  downloaded: boolean;
  filePath: string | null;
  reason: string | null;
}

export interface StitchManifestResponse {
  ok: boolean;
  projectId: string;
  screens: StitchScreen[];
}

export interface McpHealthResponse {
  ok: boolean;
  status?: number;
  upstream?: unknown;
  error?: string;
  latencyMs?: number;
}

export interface LocalHealthResponse {
  ok: boolean;
  daemonIpcAddr: string;
  logPath: string;
  mcpConfigured: boolean;
  bridgeUptimeSecs: number;
  uiOrigin: string;
}

export interface StatusSnapshotResponse {
  ok: boolean;
  daemonOk: boolean;
  daemonStatus: DaemonStatus;
  daemonMetrics: DaemonMetrics | null;
  daemonError: string | null;
  bridge: {
    apiPort: number;
    daemonIpcAddr: string;
    logPath: string;
    uptimeSecs: number;
  };
}
