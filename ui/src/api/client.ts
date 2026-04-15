import type {
  ActionResponse,
  DaemonMetricsResponse,
  DaemonStatusResponse,
  LocalHealthResponse,
  LogsResponse,
  McpHealthResponse,
  StatusSnapshotResponse,
  StitchManifestResponse
} from "../types";

async function request<T>(input: string, init?: RequestInit): Promise<T> {
  const response = await fetch(input, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    }
  });

  const payload = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new Error(payload.error ?? `Request failed with status ${response.status}`);
  }

  return payload;
}

export const api = {
  health: () => request<LocalHealthResponse>("/api/health"),
  status: () => request<StatusSnapshotResponse>("/api/status"),
  daemonStatus: () => request<DaemonStatusResponse>("/api/daemon/status"),
  daemonMetrics: () => request<DaemonMetricsResponse>("/api/daemon/metrics"),
  connect: () =>
    request<ActionResponse>("/api/daemon/connect", {
      method: "POST"
    }),
  disconnect: (adminSecret?: string) =>
    request<ActionResponse>("/api/daemon/disconnect", {
      method: "POST",
      body: JSON.stringify({
        adminSecret: adminSecret?.trim() || undefined
      })
    }),
  logs: (limit = 120) => request<LogsResponse>(`/api/logs?limit=${limit}`),
  stitchManifest: () => request<StitchManifestResponse>("/api/stitch/manifest"),
  mcpHealth: () => request<McpHealthResponse>("/api/mcp/health")
};
