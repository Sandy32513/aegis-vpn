import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useState
} from "react";
import { api } from "./api/client";
import type {
  DaemonMetrics,
  DaemonStatus,
  LocalHealthResponse,
  LogEntry,
  McpHealthResponse,
  StitchScreen
} from "./types";

const defaultStatus: DaemonStatus = {
  connected: false,
  server: null,
  session_id: null,
  active_circuit: null,
  rotation_state: null,
  mode: null,
  last_error: null,
  last_transition_at: null
};

function formatTimestamp(entry: LogEntry) {
  const rawTimestamp = entry.timestamp ?? entry.ts;
  if (!rawTimestamp) {
    return "pending";
  }

  const parsed = new Date(rawTimestamp);
  if (Number.isNaN(parsed.getTime())) {
    return rawTimestamp;
  }

  return parsed.toLocaleTimeString();
}

export default function App() {
  const [daemonStatus, setDaemonStatus] = useState<DaemonStatus>(defaultStatus);
  const [daemonMetrics, setDaemonMetrics] = useState<DaemonMetrics | null>(null);
  const [daemonError, setDaemonError] = useState<string | null>(null);
  const [bridgeHealth, setBridgeHealth] = useState<LocalHealthResponse | null>(null);
  const [mcpHealth, setMcpHealth] = useState<McpHealthResponse | null>(null);
  const [mcpError, setMcpError] = useState<string | null>(null);
  const [screens, setScreens] = useState<StitchScreen[]>([]);
  const [screenError, setScreenError] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logsStreamHealthy, setLogsStreamHealthy] = useState(false);
  const [adminSecret, setAdminSecret] = useState("");
  const [activityMessage, setActivityMessage] = useState("Waiting for local services.");
  const [busyAction, setBusyAction] = useState<"connect" | "disconnect" | null>(null);
  const [logFilter, setLogFilter] = useState("");

  const deferredLogFilter = useDeferredValue(logFilter);
  const filteredLogs = logs.filter((entry) => {
    const needle = deferredLogFilter.trim().toLowerCase();
    if (!needle) {
      return true;
    }

    return JSON.stringify(entry).toLowerCase().includes(needle);
  });

  const replaceLogs = useEffectEvent((entries: LogEntry[]) => {
    startTransition(() => {
      setLogs(entries.slice().reverse().slice(0, 160));
    });
  });

  const prependLogs = useEffectEvent((entries: LogEntry[]) => {
    startTransition(() => {
      setLogs((current) => [...entries.slice().reverse(), ...current].slice(0, 160));
    });
  });

  const refreshOverview = useEffectEvent(async () => {
    try {
      const localHealth = await api.health();
      setBridgeHealth(localHealth);
    } catch (error) {
      setActivityMessage(error instanceof Error ? error.message : "Local bridge is unavailable.");
    }

    try {
      const snapshot = await api.status();
      setDaemonStatus(snapshot.daemonStatus);
      setDaemonMetrics(snapshot.daemonMetrics);
      setDaemonError(snapshot.daemonOk ? null : snapshot.daemonError);
    } catch (error) {
      setDaemonStatus(defaultStatus);
      setDaemonMetrics(null);
      setDaemonError(error instanceof Error ? error.message : "Daemon status is unavailable.");
    }

    try {
      const manifest = await api.stitchManifest();
      setScreens(manifest.screens);
      setScreenError(null);
    } catch (error) {
      setScreenError(error instanceof Error ? error.message : "Stitch manifest could not be loaded.");
    }

    try {
      const health = await api.mcpHealth();
      setMcpHealth(health);
      setMcpError(null);
    } catch (error) {
      setMcpHealth(null);
      setMcpError(error instanceof Error ? error.message : "MCP health check failed.");
    }
  });

  useEffect(() => {
    void refreshOverview();
    const interval = window.setInterval(() => {
      void refreshOverview();
    }, 5000);

    return () => window.clearInterval(interval);
  }, [refreshOverview]);

  useEffect(() => {
    void api.logs(80)
      .then((response) => {
        replaceLogs(response.entries);
      })
      .catch(() => {
        replaceLogs([]);
      });

    const eventSource = new EventSource("/api/logs/stream");
    eventSource.onopen = () => {
      setLogsStreamHealthy(true);
    };
    eventSource.addEventListener("snapshot", (event) => {
      const message = event as MessageEvent<string>;
      replaceLogs(JSON.parse(message.data) as LogEntry[]);
    });
    eventSource.addEventListener("log", (event) => {
      const message = event as MessageEvent<string>;
      prependLogs(JSON.parse(message.data) as LogEntry[]);
    });
    eventSource.addEventListener("error", () => {
      setLogsStreamHealthy(false);
    });
    eventSource.onerror = () => {
      setLogsStreamHealthy(false);
    };

    return () => {
      eventSource.close();
    };
  }, [prependLogs, replaceLogs]);

  const runAction = useEffectEvent(async (action: "connect" | "disconnect") => {
    setBusyAction(action);

    try {
      const response =
        action === "connect"
          ? await api.connect()
          : await api.disconnect(adminSecret);

      setActivityMessage(response.message);
      if (action === "disconnect") {
        setAdminSecret("");
      }
      await refreshOverview();
    } catch (error) {
      setActivityMessage(error instanceof Error ? error.message : "Action failed.");
    } finally {
      setBusyAction(null);
    }
  });

  const downloadedCount = screens.filter((screen) => screen.downloaded).length;

  return (
    <main className="shell">
      <section className="hero panel">
        <div>
          <p className="eyebrow">Aegis VPN Development Console</p>
          <h1>Local UI, daemon IPC, Stitch exports, and MCP health in one place.</h1>
          <p className="lede">
            The browser talks only to the local bridge. Secrets stay on the server side,
            the daemon stays on loopback, and Stitch exports land in categorized folders.
          </p>
        </div>
        <div className="hero-badges">
          <span className={`badge ${daemonStatus.connected ? "badge-good" : "badge-warn"}`}>
            {daemonStatus.connected ? "Tunnel connected" : "Tunnel idle"}
          </span>
          <span className={`badge ${logsStreamHealthy ? "badge-good" : "badge-warn"}`}>
            {logsStreamHealthy ? "Live logs online" : "Logs waiting"}
          </span>
          <span className={`badge ${mcpHealth?.ok ? "badge-good" : "badge-warn"}`}>
            {mcpHealth?.ok ? "MCP healthy" : "MCP needs config"}
          </span>
        </div>
      </section>

      <section className="grid">
        <article className="panel">
          <div className="panel-head">
            <h2>Tunnel Control</h2>
            <span className="meta">{bridgeHealth?.daemonIpcAddr ?? "127.0.0.1:7788"}</span>
          </div>
          <div className="metric-stack">
            <div className="metric">
              <span>Server</span>
              <strong>{daemonStatus.server ?? "Not connected"}</strong>
            </div>
            <div className="metric">
              <span>Session</span>
              <strong>{daemonStatus.session_id ?? "n/a"}</strong>
            </div>
            <div className="metric">
              <span>Mode</span>
              <strong>{daemonStatus.mode ?? "offline"}</strong>
            </div>
            <div className="metric">
              <span>Rotation</span>
              <strong>{daemonStatus.rotation_state ?? "Unknown"}</strong>
            </div>
            <div className="metric">
              <span>Latency</span>
              <strong>{daemonMetrics?.last_connect_latency_ms ? `${daemonMetrics.last_connect_latency_ms} ms` : "n/a"}</strong>
            </div>
            <div className="metric">
              <span>Packets</span>
              <strong>{daemonMetrics ? `${daemonMetrics.packets_tx}/${daemonMetrics.packets_rx}` : "0/0"}</strong>
            </div>
            <div className="metric">
              <span>Error Rate</span>
              <strong>{daemonMetrics ? `${(daemonMetrics.error_rate * 100).toFixed(1)}%` : "0.0%"}</strong>
            </div>
          </div>
          <label className="field">
            <span>Admin secret for disconnect</span>
            <input
              type="password"
              value={adminSecret}
              onChange={(event) => setAdminSecret(event.target.value)}
              placeholder="Only needed if the daemon requires it"
            />
          </label>
          <div className="actions">
            <button
              className="button button-primary"
              type="button"
              disabled={busyAction !== null}
              onClick={() => void runAction("connect")}
            >
              {busyAction === "connect" ? "Connecting..." : "Connect"}
            </button>
            <button
              className="button button-secondary"
              type="button"
              disabled={busyAction !== null}
              onClick={() => void runAction("disconnect")}
            >
              {busyAction === "disconnect" ? "Disconnecting..." : "Disconnect"}
            </button>
          </div>
          <p className="status-line">{activityMessage}</p>
          {daemonError ? <p className="warning-text">{daemonError}</p> : null}
          {daemonStatus.last_error ? <p className="warning-text">{daemonStatus.last_error}</p> : null}
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>MCP Link</h2>
            <span className="meta">{mcpHealth?.status ? `HTTP ${mcpHealth.status}` : "Awaiting response"}</span>
          </div>
          <p className="lede small">
            The bearer token is attached by the local bridge, never by the browser bundle.
          </p>
          <div className="metric-stack">
            <div className="metric">
              <span>Configured</span>
              <strong>{bridgeHealth?.mcpConfigured ? "Yes" : "No"}</strong>
            </div>
            <div className="metric">
              <span>Health endpoint</span>
              <strong>{mcpHealth?.ok ? "Reachable" : "Not validated"}</strong>
            </div>
            <div className="metric">
              <span>Latency</span>
              <strong>{mcpHealth?.latencyMs ? `${mcpHealth.latencyMs} ms` : "n/a"}</strong>
            </div>
          </div>
          <pre className="json-box">
            {mcpError
              ? mcpError
              : JSON.stringify(mcpHealth?.upstream ?? { message: "Health response will appear here." }, null, 2)}
          </pre>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Stitch Assets</h2>
            <span className="meta">
              {downloadedCount}/{screens.length || 8} downloaded
            </span>
          </div>
          <p className="lede small">
            Fill the hosted URL env vars, then run <code>npm run download:stitch</code>.
          </p>
          {screenError ? <p className="warning-text">{screenError}</p> : null}
          <div className="screen-list">
            {screens.map((screen) => (
              <div className="screen-row" key={screen.id}>
                <div>
                  <strong>{screen.name}</strong>
                  <p>{screen.filePath ?? screen.urlEnvVar}</p>
                </div>
                <span className={`badge ${screen.downloaded ? "badge-good" : "badge-warn"}`}>
                  {screen.downloaded ? "Ready" : "Pending"}
                </span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Diagnostics</h2>
            <span className="meta">{bridgeHealth?.logPath ?? "logs/aegis-daemon.jsonl"}</span>
          </div>
          <ul className="checklist">
            <li>Daemon IPC stays on loopback only.</li>
            <li>MCP secrets live in <code>.env</code> or the OS keychain.</li>
            <li>Bridge uptime: {bridgeHealth?.bridgeUptimeSecs ?? 0}s.</li>
            <li>Stitch exports are grouped by dashboard, settings, logs, and components.</li>
            <li>Logs stream through the bridge without exposing raw credentials.</li>
          </ul>
        </article>
      </section>

      <section className="panel logs-panel">
        <div className="panel-head">
          <h2>Developer Logs & Terminal</h2>
          <span className="meta">{filteredLogs.length} visible lines</span>
        </div>
        <div className="toolbar">
          <input
            type="search"
            value={logFilter}
            onChange={(event) => setLogFilter(event.target.value)}
            placeholder="Filter by level, event, or subsystem"
          />
          <span className={`badge ${logsStreamHealthy ? "badge-good" : "badge-warn"}`}>
            {logsStreamHealthy ? "Streaming" : "Reconnect pending"}
          </span>
        </div>
        <div className="log-console">
          {filteredLogs.length === 0 ? (
            <p className="empty-state">Run the daemon to see structured logs here.</p>
          ) : (
            filteredLogs.map((entry, index) => (
              <div className="log-line" key={`${entry.raw}-${index}`}>
                <span>{formatTimestamp(entry)}</span>
                <span>{entry.level ?? "info"}</span>
                <span>{entry.event ?? entry.action ?? "event"}</span>
                <code>{entry.raw}</code>
              </div>
            ))
          )}
        </div>
      </section>
    </main>
  );
}
