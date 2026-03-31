# Aegis VPN UI Development Setup

## 1. Required VS Code extensions

Core:

- `rust-lang.rust-analyzer`: Rust language server, inlay hints, diagnostics, and cargo integration.
- `vadimcn.vscode-lldb`: Rust-native debugging from VS Code.
- `dsznajder.es7-react-js-snippets`: React/TSX productivity snippets for the UI workspace.
- `esbenp.prettier-vscode`: formatting for JSON, TS, TSX, CSS, and docs.
- `dbaeumer.vscode-eslint`: live linting and quick fixes for the UI code.
- `redhat.vscode-yaml`: YAML editing for Docker, CI, and deployment files.
- `tamasfe.even-better-toml`: TOML support for `control-plane.toml` and Rust metadata.

API and testing:

- `rangav.vscode-thunder-client`: quick health checks and local API smoke tests.
- `Postman.postman-for-vscode` (optional): collection-based API testing if your team already uses Postman.

DevOps:

- `ms-azuretools.vscode-docker`: Dockerfile and container workflow support.
- `eamodio.gitlens`: change history, blame, and code review context.
- `ms-vscode.powershell`: Windows service and setup script authoring.

Optional:

- `tauri-apps.tauri-vscode`: useful once the desktop shell moves from a plain web dev loop into Tauri packaging.
- `bradlc.vscode-tailwindcss`: optional unless Stitch exports Tailwind utility classes.

The local recommendation list is in `/.vscode/extensions.json`.

## 2. Environment setup

1. Install Node.js 24+ and npm 11+.
2. Install Rust with `rustup` so `cargo` is available in your PATH.
3. Copy `/.env.example` to `/.env`.
4. Fill in:
   - `MCP_BASE_URL`
   - `MCP_API_KEY`
   - any Stitch hosted asset URLs
5. Copy `config/control-plane.example.toml` to `config/control-plane.toml`.
6. Start the daemon:

```powershell
cargo run -p vpn-daemon -- run --config-path config/control-plane.toml
```

7. Install UI dependencies:

```powershell
cd ui
npm install
```

8. Download Stitch exports after you have hosted URLs:

```powershell
npm run download:stitch
```

9. Start the UI and local bridge:

```powershell
npm run dev
```

The Vite app runs on `http://localhost:5173`. The Node bridge runs on `http://127.0.0.1:8787`.

## 3. Secure secret handling

- Keep `.env` local only.
- Do not place `MCP_API_KEY` or admin secrets in browser code.
- The UI talks to the local Node bridge at `/api/*`.
- The Node bridge injects `Authorization: Bearer <MCP_API_KEY>` server-side.
- For Windows production use, prefer Windows Credential Manager or another OS-backed secret store over hard-coded files.

## 4. API key analysis

Current evidence in this repo supports:

- A local daemon control channel over loopback TCP IPC on `127.0.0.1:7788`.
- A remote MCP integration modeled as HTTPS REST with bearer authentication.

What is not present locally:

- No gRPC schema for MCP.
- No WebSocket contract for MCP.
- No checked-in API key or base URL.

That means the secure default is:

- `MCP_BASE_URL`: remote HTTPS endpoint
- `MCP_API_KEY`: bearer token
- `AEGIS_DAEMON_IPC_ADDR`: local daemon socket address
- `AEGIS_LOG_PATH`: local daemon log path for diagnostics streaming

## 5. Example `.env`

```dotenv
MCP_BASE_URL=https://your-mcp-server.example.com
MCP_API_KEY=replace_me
MCP_HEALTH_PATH=/health

AEGIS_DAEMON_IPC_ADDR=127.0.0.1:7788
AEGIS_LOG_PATH=logs/aegis-daemon.jsonl
AEGIS_UI_API_PORT=8787
AEGIS_UI_PORT=5173

STITCH_PROJECT_ID=4211889957954329850
STITCH_SCREEN_DASHBOARD_URL=https://hosted-stitch-export.example.com/dashboard.zip
```

## 6. Stitch download commands

PowerShell note: use `curl.exe`, not `curl`, so the real curl binary is called.

```powershell
curl.exe -L $env:STITCH_SCREEN_DESIGN_SYSTEM_URL -o ui/assets/stitch/components/design-system.zip
curl.exe -L $env:STITCH_SCREEN_DASHBOARD_URL -o ui/assets/stitch/dashboard/aegis-vpn-dashboard.zip
curl.exe -L $env:STITCH_SCREEN_SERVER_SELECTION_URL -o ui/assets/stitch/server-selection/server-selection.zip
curl.exe -L $env:STITCH_SCREEN_VPN_SETTINGS_URL -o ui/assets/stitch/settings/vpn-settings.zip
curl.exe -L $env:STITCH_SCREEN_ACCOUNT_URL -o ui/assets/stitch/account/account-subscription.zip
curl.exe -L $env:STITCH_SCREEN_DIAGNOSTICS_URL -o ui/assets/stitch/diagnostics/system-health-diagnostics.zip
curl.exe -L $env:STITCH_SCREEN_DEV_LOGS_PRIMARY_URL -o ui/assets/stitch/logs/developer-logs-terminal-primary.zip
curl.exe -L $env:STITCH_SCREEN_DEV_LOGS_SECONDARY_URL -o ui/assets/stitch/logs/developer-logs-terminal-secondary.zip
```

If you prefer automation, run `npm run download:stitch` from `ui/`.

## 7. UI folder structure

```text
ui/
├── assets/
│   └── stitch/
│       ├── account/
│       ├── components/
│       ├── dashboard/
│       ├── diagnostics/
│       ├── logs/
│       ├── server-selection/
│       └── settings/
├── scripts/
├── server/
└── src/
```

## 8. Validation checklist

- `cargo` is installed and reachable from VS Code terminal.
- `config/control-plane.toml` exists and points at a valid server endpoint.
- `MCP_BASE_URL` and `MCP_API_KEY` are set in `.env`.
- `npm run build` passes in `ui/`.
- `GET /api/health` returns `ok: true`.
- `GET /api/daemon/status` succeeds when the daemon is running.
- `GET /api/mcp/health` succeeds when the MCP server is reachable.
- `npm run download:stitch` creates files under `ui/assets/stitch/`.
- `.env` is ignored by git and not copied into frontend bundles.
