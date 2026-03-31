import express from "express";
import dotenv from "dotenv";
import fs from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { createConnection } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../..");
const uiRoot = path.resolve(repoRoot, "ui");
const distRoot = path.join(uiRoot, "dist");

dotenv.config({ path: path.join(repoRoot, ".env") });
dotenv.config({ path: path.join(uiRoot, ".env") });

const config = {
  apiPort: Number(process.env.AEGIS_UI_API_PORT ?? 8787),
  uiPort: Number(process.env.AEGIS_UI_PORT ?? 5173),
  daemonIpcAddr: process.env.AEGIS_DAEMON_IPC_ADDR ?? "127.0.0.1:7788",
  logPath: path.resolve(repoRoot, process.env.AEGIS_LOG_PATH ?? "logs/aegis-daemon.jsonl"),
  mcpBaseUrl: (process.env.MCP_BASE_URL ?? "").replace(/\/+$/, ""),
  mcpApiKey: process.env.MCP_API_KEY ?? "",
  mcpHealthPath: process.env.MCP_HEALTH_PATH ?? "/health",
  mcpTimeoutMs: Number(process.env.MCP_TIMEOUT_MS ?? 5000)
};

const app = express();
app.use(express.json({ limit: "1mb" }));

const bridgeStartedAt = Date.now();
const allowedOrigins = new Set([
  `http://127.0.0.1:${config.uiPort}`,
  `http://localhost:${config.uiPort}`,
  `http://127.0.0.1:${config.apiPort}`,
  `http://localhost:${config.apiPort}`
]);

function logBridge(level, event, fields = {}) {
  console.log(
    JSON.stringify({
      service: "ui-bridge",
      level,
      event,
      timestamp: Date.now().toString(),
      ...fields
    })
  );
}

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") {
    res.sendStatus(204);
    return;
  }
  next();
});

app.use((req, res, next) => {
  const startedAt = Date.now();
  res.on("finish", () => {
    logBridge("INFO", "http_request", {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      latency_ms: Date.now() - startedAt
    });
  });
  next();
});

function parseSocketAddress(address) {
  const lastColon = address.lastIndexOf(":");
  if (lastColon === -1) {
    throw new Error(`Invalid IPC address: ${address}`);
  }

  const host = address.slice(0, lastColon);
  const port = Number(address.slice(lastColon + 1));

  if (!host || Number.isNaN(port)) {
    throw new Error(`Invalid IPC address: ${address}`);
  }

  return { host, port };
}

function ipcPayload(action, adminSecret) {
  switch (action) {
    case "Connect":
      return JSON.stringify("Connect");
    case "Disconnect":
      return JSON.stringify({
        Disconnect: {
          admin_secret: adminSecret ?? null
        }
      });
    case "Status":
      return JSON.stringify("Status");
    case "Metrics":
      return JSON.stringify("Metrics");
    default:
      throw new Error(`Unsupported IPC action: ${action}`);
  }
}

function normalizeIpcResponse(rawResponse) {
  if (rawResponse.Ok) {
    return { kind: "ok", message: rawResponse.Ok.message };
  }

  if (rawResponse.Status) {
    return { kind: "status", status: rawResponse.Status.status };
  }

  if (rawResponse.Metrics) {
    return { kind: "metrics", metrics: rawResponse.Metrics.metrics };
  }

  if (rawResponse.Error) {
    throw new Error(rawResponse.Error.message);
  }

  throw new Error("Unknown daemon response shape");
}

function sendIpcRequest(action, adminSecret) {
  const { host, port } = parseSocketAddress(config.daemonIpcAddr);
  const payload = `${ipcPayload(action, adminSecret)}\n`;

  return new Promise((resolve, reject) => {
    const socket = createConnection({ host, port });
    let buffer = "";
    let settled = false;

    const finish = (callback) => (value) => {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      callback(value);
    };

    const resolveFromBuffer = () => {
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex === -1) {
        return;
      }

      const line = buffer.slice(0, newlineIndex).trim();
      finish((rawLine) => {
        if (!rawLine) {
          reject(new Error("Daemon returned an empty response"));
          return;
        }

        try {
          resolve(normalizeIpcResponse(JSON.parse(rawLine)));
        } catch (error) {
          reject(error);
        }
      })(line);
    };

    socket.setEncoding("utf8");
    socket.setTimeout(4000);
    socket.on("connect", () => {
      socket.write(payload);
    });
    socket.on("data", (chunk) => {
      buffer += chunk;
      resolveFromBuffer();
    });
    socket.on("timeout", finish(() => reject(new Error("Timed out waiting for the daemon IPC response"))));
    socket.on("error", finish((error) => reject(error)));
    socket.on(
      "end",
      finish(() => {
        if (buffer.trim()) {
          try {
            resolve(normalizeIpcResponse(JSON.parse(buffer.trim())));
            return;
          } catch (error) {
            reject(error);
            return;
          }
        }

        reject(new Error("Daemon closed the IPC connection before replying"));
      })
    );
  });
}

function parseLogLine(line) {
  try {
    const parsed = JSON.parse(line);
    return {
      ...parsed,
      raw: line
    };
  } catch {
    return {
      raw: line,
      level: "unknown",
      event: "unparsed_log_line"
    };
  }
}

async function readLogEntries(limit = 120) {
  try {
    const raw = await readFile(config.logPath, "utf8");
    return raw
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-limit)
      .map(parseLogLine);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

async function readStitchManifest() {
  const manifest = JSON.parse(await readFile(path.join(uiRoot, "stitch-manifest.json"), "utf8"));
  let report = { screens: [] };

  try {
    report = JSON.parse(await readFile(path.join(uiRoot, "assets", "stitch", "download-report.json"), "utf8"));
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
      throw error;
    }
  }

  const byId = new Map(report.screens.map((screen) => [screen.id, screen]));

  return {
    projectId: manifest.projectId,
    screens: manifest.screens.map((screen) => {
      const result = byId.get(screen.id);
      return {
        ...screen,
        downloaded: Boolean(result?.downloaded),
        filePath: result?.filePath ?? null,
        reason: result?.reason ?? null
      };
    })
  };
}

async function getDaemonSnapshot() {
  try {
    const [statusResponse, metricsResponse] = await Promise.all([
      sendIpcRequest("Status"),
      sendIpcRequest("Metrics")
    ]);

    if (statusResponse.kind !== "status") {
      throw new Error("Daemon status response had an unexpected shape");
    }

    if (metricsResponse.kind !== "metrics") {
      throw new Error("Daemon metrics response had an unexpected shape");
    }

    return {
      daemonOk: true,
      daemonStatus: statusResponse.status,
      daemonMetrics: metricsResponse.metrics,
      daemonError: null
    };
  } catch (error) {
    return {
      daemonOk: false,
      daemonStatus: {
        connected: false,
        server: null,
        session_id: null,
        active_circuit: null,
        rotation_state: null,
        mode: null,
        last_error: null,
        last_transition_at: null
      },
      daemonMetrics: null,
      daemonError: error instanceof Error ? error.message : "Failed to reach the daemon"
    };
  }
}

function requireMcpConfig() {
  if (!config.mcpBaseUrl || !config.mcpApiKey) {
    const error = new Error("MCP_BASE_URL and MCP_API_KEY must be set in .env");
    error.statusCode = 400;
    throw error;
  }
}

async function fetchMcp(pathSuffix, options = {}) {
  requireMcpConfig();
  const startedAt = Date.now();

  const response = await fetch(`${config.mcpBaseUrl}${pathSuffix}`, {
    ...options,
    signal: AbortSignal.timeout(config.mcpTimeoutMs),
    headers: {
      Authorization: `Bearer ${config.mcpApiKey}`,
      "Content-Type": "application/json",
      ...(options.headers ?? {})
    }
  });

  const text = await response.text();
  let body;

  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  return {
    ok: response.ok,
    status: response.status,
    body,
    latencyMs: Date.now() - startedAt
  };
}

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    daemonIpcAddr: config.daemonIpcAddr,
    logPath: path.relative(repoRoot, config.logPath),
    mcpConfigured: Boolean(config.mcpBaseUrl && config.mcpApiKey),
    bridgeUptimeSecs: Math.floor((Date.now() - bridgeStartedAt) / 1000),
    uiOrigin: `http://127.0.0.1:${config.uiPort}`
  });
});

app.get("/api/status", async (_req, res) => {
  const snapshot = await getDaemonSnapshot();
  res.json({
    ok: true,
    daemonOk: snapshot.daemonOk,
    daemonStatus: snapshot.daemonStatus,
    daemonMetrics: snapshot.daemonMetrics,
    daemonError: snapshot.daemonError,
    bridge: {
      apiPort: config.apiPort,
      daemonIpcAddr: config.daemonIpcAddr,
      logPath: path.relative(repoRoot, config.logPath),
      uptimeSecs: Math.floor((Date.now() - bridgeStartedAt) / 1000)
    }
  });
});

app.get("/api/daemon/status", async (_req, res) => {
  try {
    const response = await sendIpcRequest("Status");
    res.json({ ok: true, ...response });
  } catch (error) {
    res.status(502).json({
      ok: false,
      error: error instanceof Error ? error.message : "Failed to reach the daemon"
    });
  }
});

app.get("/api/daemon/metrics", async (_req, res) => {
  try {
    const response = await sendIpcRequest("Metrics");
    res.json({ ok: true, ...response });
  } catch (error) {
    res.status(502).json({
      ok: false,
      error: error instanceof Error ? error.message : "Daemon metrics are unavailable"
    });
  }
});

app.post("/api/daemon/connect", async (_req, res) => {
  try {
    const response = await sendIpcRequest("Connect");
    res.json({ ok: true, ...response });
  } catch (error) {
    res.status(502).json({
      ok: false,
      error: error instanceof Error ? error.message : "Connect request failed"
    });
  }
});

app.post("/api/daemon/disconnect", async (req, res) => {
  try {
    const response = await sendIpcRequest("Disconnect", req.body?.adminSecret);
    res.json({ ok: true, ...response });
  } catch (error) {
    res.status(502).json({
      ok: false,
      error: error instanceof Error ? error.message : "Disconnect request failed"
    });
  }
});

app.get("/api/logs", async (req, res) => {
  try {
    const requestedLimit = Number(req.query.limit ?? 120);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 500) : 120;
    const entries = await readLogEntries(limit);
    res.json({ ok: true, entries });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error instanceof Error ? error.message : "Unable to read local logs"
    });
  }
});

app.get("/api/logs/stream", async (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const sendEvent = (eventName, payload) => {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  };

  let lastSize = 0;
  let busy = false;

  try {
    const snapshot = await readLogEntries(120);
    sendEvent("snapshot", snapshot);

    try {
      lastSize = (await stat(config.logPath)).size;
    } catch {
      lastSize = 0;
    }
  } catch (error) {
    sendEvent("error", {
      message: error instanceof Error ? error.message : "Unable to create log snapshot"
    });
  }

  const timer = setInterval(async () => {
    if (busy) {
      return;
    }

    busy = true;

    try {
      let fileStats;

      try {
        fileStats = await stat(config.logPath);
      } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
          return;
        }

        throw error;
      }

      if (fileStats.size < lastSize) {
        lastSize = 0;
      }

      if (fileStats.size === lastSize) {
        return;
      }

      const stream = fs.createReadStream(config.logPath, {
        start: lastSize,
        end: fileStats.size - 1,
        encoding: "utf8"
      });

      let delta = "";
      for await (const chunk of stream) {
        delta += chunk;
      }

      lastSize = fileStats.size;

      const entries = delta
        .split(/\r?\n/)
        .filter(Boolean)
        .map(parseLogLine);

      if (entries.length > 0) {
        sendEvent("log", entries);
      }
    } catch (error) {
      sendEvent("error", {
        message: error instanceof Error ? error.message : "Log stream failed"
      });
    } finally {
      busy = false;
    }
  }, 1500);

  req.on("close", () => {
    clearInterval(timer);
    res.end();
  });
});

app.get("/api/stitch/manifest", async (_req, res) => {
  try {
    res.json({ ok: true, ...(await readStitchManifest()) });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error instanceof Error ? error.message : "Unable to read Stitch manifest"
    });
  }
});

app.get("/api/mcp/health", async (_req, res) => {
  try {
    const response = await fetchMcp(config.mcpHealthPath, { method: "GET" });
    res.status(response.status).json({
      ok: response.ok,
      status: response.status,
      upstream: response.body,
      latencyMs: response.latencyMs
    });
  } catch (error) {
    const statusCode = error instanceof Error && "statusCode" in error ? error.statusCode : 500;
    res.status(statusCode).json({
      ok: false,
      error: error instanceof Error ? error.message : "Unable to reach MCP server"
    });
  }
});

app.post("/api/mcp/request", async (req, res) => {
  try {
    const pathSuffix = String(req.body?.path ?? "").trim();
    if (!pathSuffix || pathSuffix.startsWith("http")) {
      res.status(400).json({ ok: false, error: "Provide a relative MCP path such as /sessions or /health" });
      return;
    }

    const method = String(req.body?.method ?? "GET").toUpperCase();
    const response = await fetchMcp(pathSuffix.startsWith("/") ? pathSuffix : `/${pathSuffix}`, {
      method,
      body: req.body?.body ? JSON.stringify(req.body.body) : undefined
    });

    res.status(response.status).json({
      ok: response.ok,
      status: response.status,
      upstream: response.body,
      latencyMs: response.latencyMs
    });
  } catch (error) {
    const statusCode = error instanceof Error && "statusCode" in error ? error.statusCode : 500;
    res.status(statusCode).json({
      ok: false,
      error: error instanceof Error ? error.message : "MCP proxy request failed"
    });
  }
});

if (fs.existsSync(distRoot)) {
  app.use(express.static(distRoot));

  app.get(/^(?!\/api).*/, (_req, res) => {
    res.sendFile(path.join(distRoot, "index.html"));
  });
}

app.listen(config.apiPort, "127.0.0.1", () => {
  logBridge("INFO", "bridge_listening", {
    url: `http://127.0.0.1:${config.apiPort}`,
    daemonIpcAddr: config.daemonIpcAddr
  });
});
