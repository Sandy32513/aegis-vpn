import http from "node:http";

const port = Number(process.env.MOCK_MCP_PORT ?? 8799);
const token = process.env.MOCK_MCP_TOKEN ?? process.env.MCP_API_KEY ?? "aegis-dev-token";

function writeJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  });
  res.end(JSON.stringify(payload));
}

function collectBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    writeJson(res, 204, {});
    return;
  }

  const auth = req.headers.authorization ?? "";
  if (auth !== `Bearer ${token}`) {
    writeJson(res, 401, {
      ok: false,
      error: "invalid_token"
    });
    return;
  }

  if (req.method === "GET" && req.url === "/health") {
    writeJson(res, 200, {
      ok: true,
      service: "mock-mcp",
      timestamp: Date.now().toString()
    });
    return;
  }

  if (req.method === "GET" && req.url === "/sessions") {
    writeJson(res, 200, {
      ok: true,
      sessions: [
        {
          id: "session-local-1",
          state: "ready"
        }
      ]
    });
    return;
  }

  if (req.method === "POST" && req.url === "/sessions") {
    const rawBody = await collectBody(req);
    let parsedBody = null;
    try {
      parsedBody = rawBody ? JSON.parse(rawBody) : null;
    } catch {
      parsedBody = rawBody;
    }

    writeJson(res, 201, {
      ok: true,
      created: true,
      echo: parsedBody
    });
    return;
  }

  writeJson(res, 404, {
    ok: false,
    error: "not_found",
    path: req.url
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log(
    JSON.stringify({
      service: "mock-mcp",
      level: "INFO",
      event: "listening",
      timestamp: Date.now().toString(),
      url: `http://127.0.0.1:${port}`,
      token
    })
  );
});
