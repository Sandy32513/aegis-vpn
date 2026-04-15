use crate::features::ConnectionQuality;
use crate::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum KillSwitchLevel {
    Off,
    Warning,
    Partial,
    Full,
}

impl KillSwitchLevel {
    pub fn threshold(&self) -> u8 {
        match self {
            KillSwitchLevel::Off => 0,
            KillSwitchLevel::Warning => 30,
            KillSwitchLevel::Partial => 60,
            KillSwitchLevel::Full => 90,
        }
    }

    pub fn requires_action(&self) -> bool {
        matches!(self, KillSwitchLevel::Warning | KillSwitchLevel::Partial | KillSwitchLevel::Full)
    }
}

pub struct AdaptiveKillSwitch {
    state: Arc<RwLock<KillSwitchState>>,
    config: KillSwitchConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillSwitchConfig {
    pub warning_threshold: f64,
    pub partial_threshold: f64,
    pub full_threshold: f64,
    pub auto_recover: bool,
    pub recovery_timeout_secs: u64,
    pub sensitivity: Sensitivity,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Sensitivity {
    Paranoid,
    High,
    Medium,
    Low,
    Relaxed,
}

#[derive(Clone, Debug)]
struct KillSwitchState {
    current_level: KillSwitchLevel,
    health_score: f64,
    last_change_timestamp: i64,
    consecutive_failures: u32,
    is_active: bool,
    last_warning_server: Option<String>,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        Self {
            warning_threshold: 70.0,
            partial_threshold: 50.0,
            full_threshold: 30.0,
            auto_recover: true,
            recovery_timeout_secs: 30,
            sensitivity: Sensitivity::Medium,
        }
    }
}

impl AdaptiveKillSwitch {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(KillSwitchState {
                current_level: KillSwitchLevel::Off,
                health_score: 100.0,
                last_change_timestamp: unix_millis(),
                consecutive_failures: 0,
                is_active: false,
                last_warning_server: None,
            })),
            config: KillSwitchConfig::default(),
        }
    }

    pub fn with_config(config: KillSwitchConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(KillSwitchState {
                current_level: KillSwitchLevel::Off,
                health_score: 100.0,
                last_change_timestamp: unix_millis(),
                consecutive_failures: 0,
                is_active: false,
                last_warning_server: None,
            })),
            config,
        }
    }

    pub fn set_sensitivity(&mut self, sensitivity: Sensitivity) {
        self.config.sensitivity = sensitivity;
    }

    pub fn update_health(&self, score: f64) {
        let mut state = self.state.write();
        state.health_score = score;

        let new_level = self.calculate_level(score);
        if new_level != state.current_level {
            state.current_level = new_level.clone();
            state.last_change_timestamp = unix_millis();
            state.is_active = new_level.requires_action();
        }
    }

    pub fn record_latency_spike(&self, latency_ms: u64) {
        let mut state = self.state.write();

        if latency_ms > 100 {
            state.consecutive_failures += 1;
        } else if state.consecutive_failures > 0 {
            state.consecutive_failures = state.consecutive_failures.saturating_sub(1);
        }

        state.health_score = self.calculate_health_score(state.consecutive_failures);
        let new_level = self.calculate_level(state.health_score);

        if new_level != state.current_level {
            state.current_level = new_level;
            state.last_change_timestamp = unix_millis();
            state.is_active = new_level.requires_action();
        }
    }

    pub fn record_packet_loss(&self, loss_rate: f64) {
        let mut state = self.state.write();

        if loss_rate > 0.05 {
            state.consecutive_failures += 2;
        } else if loss_rate > 0.01 {
            state.consecutive_failures += 1;
        } else {
            state.consecutive_failures = state.consecutive_failures.saturating_sub(1);
        }

        state.health_score = self.calculate_health_score(state.consecutive_failures);
        let new_level = self.calculate_level(state.health_score);

        if new_level != state.current_level {
            state.current_level = new_level;
            state.last_change_timestamp = unix_millis();
            state.is_active = new_level.requires_action();
        }
    }

    pub fn record_connection_failure(&self, server: Option<String>) {
        let mut state = self.state.write();
        state.consecutive_failures += 3;
        state.last_warning_server = server;
        state.health_score = self.calculate_health_score(state.consecutive_failures);
        let new_level = self.calculate_level(state.health_score);

        if new_level != state.current_level {
            state.current_level = new_level;
            state.last_change_timestamp = unix_millis();
            state.is_active = new_level.requires_action();
        }
    }

    pub fn record_connection_success(&self) {
        let mut state = self.state.write();
        state.consecutive_failures = state.consecutive_failures.saturating_sub(1);
        state.health_score = self.calculate_health_score(state.consecutive_failures);

        let new_level = self.calculate_level(state.health_score);
        if new_level != state.current_level {
            state.current_level = new_level;
            state.is_active = new_level.requires_action();
        }
    }

    fn calculate_health_score(&self, failures: u32) -> f64 {
        let base = 100.0;
        let penalty = (failures as f64 * 10.0).min(base);
        (base - penalty).max(0.0).min(100.0)
    }

    fn calculate_level(&self, score: f64) -> KillSwitchLevel {
        match self.config.sensitivity {
            Sensitivity::Paranoid => {
                if score >= 70.0 {
                    KillSwitchLevel::Off
                } else if score >= 50.0 {
                    KillSwitchLevel::Warning
                } else if score >= 30.0 {
                    KillSwitchLevel::Partial
                } else {
                    KillSwitchLevel::Full
                }
            }
            Sensitivity::High => {
                if score >= 60.0 {
                    KillSwitchLevel::Off
                } else if score >= 40.0 {
                    KillSwitchLevel::Warning
                } else if score >= 20.0 {
                    KillSwitchLevel::Partial
                } else {
                    KillSwitchLevel::Full
                }
            }
            Sensitivity::Medium => {
                if score >= self.config.warning_threshold {
                    KillSwitchLevel::Off
                } else if score >= self.config.partial_threshold {
                    KillSwitchLevel::Warning
                } else if score >= self.config.full_threshold {
                    KillSwitchLevel::Partial
                } else {
                    KillSwitchLevel::Full
                }
            }
            Sensitivity::Low => {
                if score >= 40.0 {
                    KillSwitchLevel::Off
                } else if score >= 20.0 {
                    KillSwitchLevel::Warning
                } else {
                    KillSwitchLevel::Partial
                }
            }
            Sensitivity::Relaxed => {
                if score >= 30.0 {
                    KillSwitchLevel::Off
                } else if score >= 10.0 {
                    KillSwitchLevel::Warning
                } else {
                    KillSwitchLevel::Partial
                }
            }
        }
    }

    pub fn current_level(&self) -> KillSwitchLevel {
        self.state.read().current_level.clone()
    }

    pub fn health_score(&self) -> f64 {
        self.state.read().health_score
    }

    pub fn is_active(&self) -> bool {
        self.state.read().is_active
    }

    pub fn should_block_traffic(&self) -> bool {
        let state = self.state.read();
        matches!(
            state.current_level,
            KillSwitchLevel::Partial | KillSwitchLevel::Full
        )
    }

    pub fn should_warn_user(&self) -> bool {
        let state = self.state.read();
        state.current_level == KillSwitchLevel::Warning
    }

    pub fn should_reconnect(&self) -> bool {
        let state = self.state.read();
        matches!(state.current_level, KillSwitchLevel::Full)
            && self.config.auto_recover
            && (unix_millis() - state.last_change_timestamp) > (self.config.recovery_timeout_secs as i64 * 1000)
    }

    pub fn reset(&self) {
        let mut state = self.state.write();
        state.current_level = KillSwitchLevel::Off;
        state.health_score = 100.0;
        state.consecutive_failures = 0;
        state.is_active = false;
    }

    pub fn status(&self) -> KillSwitchStatus {
        let state = self.state.read();
        KillSwitchStatus {
            level: state.current_level.clone(),
            health_score: state.health_score,
            is_active: state.is_active,
            consecutive_failures: state.consecutive_failures,
            last_change_timestamp: state.last_change_timestamp,
        }
    }
}

impl Default for AdaptiveKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub level: KillSwitchLevel,
    pub health_score: f64,
    pub is_active: bool,
    pub consecutive_failures: u32,
    pub last_change_timestamp: i64,
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}