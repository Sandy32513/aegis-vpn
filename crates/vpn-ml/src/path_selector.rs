use crate::features::{FeatureExtractor, NetworkFeatures};
use crate::Result;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub hostname: String,
    pub region: String,
    pub latency_ms: Option<f64>,
    pub load: f64,
    pub success_rate: f64,
    pub last_selected: Option<i64>,
}

impl Server {
    pub fn new(id: String, hostname: String, region: String) -> Self {
        Self {
            id,
            hostname,
            region,
            latency_ms: None,
            load: 0.5,
            success_rate: 0.95,
            last_selected: None,
        }
    }

    pub fn score(&self, features: &NetworkFeatures) -> f64 {
        let latency_score = if let Some(latency) = self.latency_ms {
            if latency < 30.0 {
                1.0
            } else if latency < 100.0 {
                0.8
            } else if latency < 200.0 {
                0.5
            } else {
                0.2
            }
        } else {
            0.5
        };

        let load_score = 1.0 - self.load;
        let success_score = self.success_rate;

        (latency_score * 0.4 + load_score * 0.3 + success_score * 0.3)
            .max(0.0)
            .min(1.0)
    }
}

pub struct PathSelector {
    servers: HashMap<String, Server>,
    feature_extractor: FeatureExtractor,
    selection_mode: SelectionMode,
    history: Vec<SelectionRecord>,
    max_history: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SelectionMode {
    Random,
    Latency,
    Load,
    ML,
    Failover,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectionRecord {
    pub session_id: String,
    pub server_id: String,
    pub timestamp: i64,
    pub success: bool,
    pub latency_ms: Option<f64>,
}

impl PathSelector {
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
            feature_extractor: FeatureExtractor::new(100),
            selection_mode: SelectionMode::Latency,
            history: Vec::new(),
            max_history: 1000,
        }
    }

    pub fn add_server(&mut self, server: Server) {
        self.servers.insert(server.id.clone(), server);
    }

    pub fn remove_server(&mut self, server_id: &str) {
        self.servers.remove(server_id);
    }

    pub fn servers(&self) -> Vec<&Server> {
        self.servers.values().collect()
    }

    pub fn set_selection_mode(&mut self, mode: SelectionMode) {
        self.selection_mode = mode;
    }

    pub fn select_server(&mut self) -> Option<String> {
        if self.servers.is_empty() {
            return None;
        }

        let features = self.feature_extractor.extract_features();

        let server_id = match self.selection_mode {
            SelectionMode::Random => self.select_random(),
            SelectionMode::Latency => self.select_by_latency(),
            SelectionMode::Load => self.select_by_load(),
            SelectionMode::ML => self.select_ml(&features),
            SelectionMode::Failover => self.select_failover(&features),
        };

        if let Some(ref id) = server_id {
            if let Some(server) = self.servers.get_mut(id) {
                server.last_selected = Some(unix_millis() as i64);
            }
        }

        server_id
    }

    fn select_random(&self) -> Option<String> {
        let mut rng = rand::thread_rng();
        let server_ids: Vec<_> = self.servers.keys().collect();
        server_ids.choose(&mut rng).map(|s| s.to_string())
    }

    fn select_by_latency(&self) -> Option<String> {
        let mut sorted: Vec<_> = self.servers.values().collect();
        sorted.sort_by(|a, b| {
            let a_lat = a.latency_ms.unwrap_or(f64::MAX);
            let b_lat = b.latency_ms.unwrap_or(f64::MAX);
            a_lat.partial_cmp(&b_lat).unwrap()
        });
        sorted.into_iter().next().map(|s| s.id.clone())
    }

    fn select_by_load(&self) -> Option<String> {
        let mut sorted: Vec<_> = self.servers.values().collect();
        sorted.sort_by(|a, b| {
            a.load.partial_cmp(&b.load).unwrap()
        });
        sorted.into_iter().next().map(|s| s.id.clone())
    }

    fn select_ml(&self, features: &NetworkFeatures) -> Option<String> {
        let mut candidates: Vec<_> = self.servers.values().collect();
        
        if candidates.is_empty() {
            return None;
        }

        for server in &candidates {
            if server.load > 0.9 || server.success_rate < 0.8 {
                continue;
            }
        }

        candidates.sort_by(|a, b| {
            let a_score = a.score(features);
            let b_score = b.score(features);
            b_score.partial_cmp(&a_score).unwrap()
        });

        candidates.into_iter().next().map(|s| s.id.clone())
    }

    fn select_failover(&self, features: &NetworkFeatures) -> Option<String> {
        let quality = &features.connection_quality;

        if quality.is_good() || quality.is_acceptable() {
            return self.select_by_latency();
        }

        self.select_random()
    }

    pub fn record_selection(&mut self, session_id: &str, server_id: &str, success: bool, latency_ms: Option<f64>) {
        let record = SelectionRecord {
            session_id: session_id.to_string(),
            server_id: server_id.to_string(),
            timestamp: unix_millis(),
            success,
            latency_ms,
        };

        self.history.push(record);
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }

        if let Some(server) = self.servers.get_mut(server_id) {
            if success {
                server.success_rate = (server.success_rate * 0.95 + 0.05).min(1.0);
            } else {
                server.success_rate = (server.success_rate * 0.95).max(0.0);
            }
        }
    }

    pub fn update_latency(&mut self, server_id: &str, latency_ms: f64) {
        if let Some(server) = self.servers.get_mut(server_id) {
            server.latency_ms = Some(latency_ms);
        }
        self.feature_extractor.record_latency(latency_ms);
    }

    pub fn update_load(&mut self, server_id: &str, load: f64) {
        if let Some(server) = self.servers.get_mut(server_id) {
            server.load = load;
        }
    }

    pub fn feature_extractor(&self) -> &FeatureExtractor {
        &self.feature_extractor
    }

    pub fn success_rate(&self) -> f64 {
        if self.history.is_empty() {
            return 0.95;
        }
        let successful = self.history.iter().filter(|r| r.success).count();
        successful as f64 / self.history.len() as f64
    }

    pub fn record_result(&mut self, session_id: &str, success: bool) {
        if let Some(record) = self.history.iter_mut().find(|r| r.session_id == session_id) {
            record.success = success;
        }

        let server_id = if let Some(record) = self.history.iter().find(|r| r.session_id == session_id) {
            &record.server_id
        } else {
            return;
        };

        if let Some(server) = self.servers.get_mut(server_id) {
            if success {
                server.success_rate = (server.success_rate * 0.95 + 0.05).min(1.0);
            } else {
                server.success_rate = (server.success_rate * 0.9).max(0.0);
            }
        }
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}

trait QualityExt {
    fn is_good(&self) -> bool;
    fn is_acceptable(&self) -> bool;
}

impl QualityExt for crate::features::ConnectionQuality {
    fn is_good(&self) -> bool {
        matches!(self, crate::features::ConnectionQuality::Good)
    }

    fn is_acceptable(&self) -> bool {
        matches!(self, crate::features::ConnectionQuality::Acceptable)
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}