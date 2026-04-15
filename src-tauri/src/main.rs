#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};

#[derive(Default)]
struct AppState {
    connected: Mutex<bool>,
    server: Mutex<Option<String>>,
    minimize_to_tray: Mutex<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DaemonStatus {
    connected: bool,
    server: Option<String>,
    session_id: Option<String>,
    active_circuit: Option<String>,
    rotation_state: Option<String>,
    mode: Option<String>,
    last_error: Option<String>,
    last_transition_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DaemonMetrics {
    mode: String,
    uptime_secs: u64,
    last_connect_latency_ms: Option<u64>,
    packets_tx: u64,
    packets_rx: u64,
    request_count: u64,
    error_count: u64,
    error_rate: f64,
    connect_count: u64,
    disconnect_count: u64,
    last_transition_at: Option<String>,
}

#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<String, String> {
    let client = reqwest::Client::new();
    let addr = "127.0.0.1:7788";

    match client
        .post(format!("http://{}/connect", addr))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                *state.connected.lock().unwrap() = true;
                Ok("Connected".to_string())
            } else {
                Err(format!("Connection failed: {}", resp.status()))
            }
        }
        Err(e) => Err(format!("Daemon unavailable: {}", e)),
    }
}

#[tauri::command]
async fn disconnect(
    admin_secret: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let addr = "127.0.0.1:7788";

    let mut req = client.post(format!("http://{}/disconnect", addr));
    if let Some(secret) = admin_secret {
        req = req.header("Authorization", format!("Bearer {}", secret));
    }

    match req.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                *state.connected.lock().unwrap() = false;
                *state.server.lock().unwrap() = None;
                Ok("Disconnected".to_string())
            } else {
                Err(format!("Disconnect failed: {}", resp.status()))
            }
        }
        Err(e) => Err(format!("Daemon unavailable: {}", e)),
    }
}

#[tauri::command]
async fn status() -> Result<DaemonStatus, String> {
    let client = reqwest::Client::new();
    let addr = "127.0.0.1:7788";

    match client
        .get(format!("http://{}/status", addr))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<DaemonStatus>()
                    .await
                    .map_err(|e| format!("Parse error: {}", e))
            } else {
                Ok(default_status())
            }
        }
        Err(_) => Ok(default_status()),
    }
}

fn default_status() -> DaemonStatus {
    DaemonStatus {
        connected: false,
        server: None,
        session_id: None,
        active_circuit: None,
        rotation_state: None,
        mode: Some("offline".to_string()),
        last_error: None,
        last_transition_at: None,
    }
}

#[tauri::command]
async fn metrics() -> Result<DaemonMetrics, String> {
    let client = reqwest::Client::new();
    let addr = "127.0.0.1:7788";

    match client
        .get(format!("http://{}/metrics", addr))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<DaemonMetrics>()
                    .await
                    .map_err(|e| format!("Parse error: {}", e))
            } else {
                Ok(default_metrics())
            }
        }
        Err(_) => Ok(default_metrics()),
    }
}

fn default_metrics() -> DaemonMetrics {
    DaemonMetrics {
        mode: "offline".to_string(),
        uptime_secs: 0,
        last_connect_latency_ms: None,
        packets_tx: 0,
        packets_rx: 0,
        request_count: 0,
        error_count: 0,
        error_rate: 0.0,
        connect_count: 0,
        disconnect_count: 0,
        last_transition_at: None,
    }
}

#[tauri::command]
fn get_connected(state: State<'_, AppState>) -> bool {
    *state.connected.lock().unwrap()
}

#[tauri::command]
fn set_server(server: String, state: State<'_, AppState>) {
    *state.server.lock().unwrap() = Some(server);
}

#[tauri::command]
fn set_minimize_to_tray(enable: bool, state: State<'_, AppState>) {
    *state.minimize_to_tray.lock().unwrap() = enable;
}

#[tauri::command]
fn get_minimize_to_tray(state: State<'_, AppState>) -> bool {
    *state.minimize_to_tray.lock().unwrap()
}

#[tauri::command]
async fn show_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn hide_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .setup(|app| {
            let handle = app.handle().clone();

            let quit_item = MenuItem::with_id(app, "quit", "Exit", true, None::<&str>)?;
            let show_item = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let connect_item = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
            let disconnect_item =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;

            let menu = Menu::with_items(
                app,
                &[
                    &connect_item,
                    &disconnect_item,
                    &show_item,
                    &quit_item,
                ],
            )?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "connect" => {
                        let handle = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let client = reqwest::Client::new();
                            let addr = "127.0.0.1:7788";
                            if let Ok(resp) = client.post(format!("http://{}/connect", addr)).send().await {
                                if resp.status().is_success() {
                                    let _ = handle.emit("tray-status", "Connected");
                                }
                            }
                        });
                    }
                    "disconnect" => {
                        let handle = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let client = reqwest::Client::new();
                            let addr = "127.0.0.1:7788";
                            if let Ok(resp) = client
                                .post(format!("http://{}/disconnect", addr))
                                .send()
                                .await
                            {
                                if resp.status().is_success() {
                                    let _ = handle.emit("tray-status", "Disconnected");
                                }
                            }
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            let window = app.get_webview_window("main").unwrap();
            window.set_title("Aegis VPN").ok();

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                if let Some(state) = app.try_state::<AppState>() {
                    if *state.minimize_to_tray.lock().unwrap() {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            status,
            metrics,
            get_connected,
            set_server,
            set_minimize_to_tray,
            get_minimize_to_tray,
            show_window,
            hide_window,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}