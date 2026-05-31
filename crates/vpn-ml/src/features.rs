use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkFeatures {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_rate: f64,
    pub bandwidth_mbps: f64,
    pub server_load: f64,
    pub time_of_day_hour: u8,
    pub day_of_week: u8,
    pub connection_quality: ConnectionQuality,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionQuality {
    Good,
    Acceptable,
    Poor,
    Critical,
}

impl NetworkFeatures {
    pub fn score(&self) -> f64 {
        let latency_score = match self.connection_quality {
            ConnectionQuality::Good => 1.0,
            ConnectionQuality::Acceptable => 0.7,
            ConnectionQuality::Poor => 0.4,
            ConnectionQuality::Critical => 0.1,
        };

        let loss_penalty = (self.packet_loss_rate * 10.0).min(1.0);

        (latency_score * (1.0 - loss_penalty)).max(0.0).min(1.0)
    }
}

pub struct FeatureExtractor {
    latency_history: Arc<RwLock<VecDeque<f64>>>,
    jitter_history: Arc<RwLock<VecDeque<f64>>>,
    packet_loss_history: Arc<RwLock<VecDeque<f64>>>,
    bandwidth_history: Arc<RwLock<VecDeque<f64>>>,
    max_history: usize,
}

impl FeatureExtractor {
    pub fn new(max_history: usize) -> Self {
        Self {
            latency_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            jitter_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            packet_loss_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            bandwidth_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            max_history,
        }
    }

    pub fn record_latency(&self, latency_ms: f64) {
        let mut history = self.latency_history.write();
        if history.len() >= self.max_history {
            history.pop_front();
        }
        history.push_back(latency_ms);
    }

    pub fn record_jitter(&self, jitter_ms: f64) {
        let mut history = self.jitter_history.write();
        if history.len() >= self.max_history {
            history.pop_front();
        }
        history.push_back(jitter_ms);
    }

    pub fn record_packet_loss(&self, loss_rate: f64) {
        let mut history = self.packet_loss_history.write();
        if history.len() >= self.max_history {
            history.pop_front();
        }
        history.push_back(loss_rate);
    }

    pub fn record_bandwidth(&self, bandwidth_mbps: f64) {
        let mut history = self.bandwidth_history.write();
        if history.len() >= self.max_history {
            history.pop_front();
        }
        history.push_back(bandwidth_mbps);
    }

    pub fn extract_features(&self) -> NetworkFeatures {
        let latency = self.average(&self.latency_history);
        let jitter = self.average(&self.jitter_history);
        let packet_loss = self.average(&self.packet_loss_history);
        let bandwidth = self.average(&self.bandwidth_history);
        
        let now = chrono::Local::now();
        let time_of_day_hour = now.hour() as u8;
        let day_of_week = now.weekday().num_days_from_monday() as u8;

        let connection_quality = self.classify_quality(latency, packet_loss, bandwidth);

        NetworkFeatures {
            latency_ms: latency,
            jitter_ms: jitter,
            packet_loss_rate: packet_loss,
            bandwidth_mbps: bandwidth,
            server_load: 0.5,
            time_of_day_hour,
            day_of_week,
            connection_quality,
        }
    }

    fn average(&self, history: &RwLock<VecDeque<f64>>) -> f64 {
        let data = history.read();
        if data.is_empty() {
            return 0.0;
        }
        data.iter().sum::<f64>() / data.len() as f64
    }

    fn classify_quality(&self, latency: f64, packet_loss: f64, bandwidth: f64) -> ConnectionQuality {
        if latency < 50.0 && packet_loss < 0.01 && bandwidth > 10.0 {
            ConnectionQuality::Good
        } else if latency < 150.0 && packet_loss < 0.05 && bandwidth > 5.0 {
            ConnectionQuality::Acceptable
        } else if latency < 300.0 && packet_loss < 0.15 && bandwidth > 1.0 {
            ConnectionQuality::Poor
        } else {
            ConnectionQuality::Critical
        }
    }

    pub fn current_latency(&self) -> Option<f64> {
        self.latency_history.read().back().copied()
    }

    pub fn latency_variance(&self) -> f64 {
        let data = self.latency_history.read();
        if data.len() < 2 {
            return 0.0;
        }
        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let variance = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / data.len() as f64;
        variance.sqrt()
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new(100)
    }
}

mod chrono {
    pub struct Local {
        pub hour: u32,
        pub weekday: Weekday,
    }

    pub struct Weekday {
        pub num_days_from_monday: u32,
    }

    impl Local {
        pub fn now() -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            let secs = now.as_secs();
            let hour = ((secs / 3600) % 24) as u32;
            let days = secs / 86400;
            let weekday = (days % 7) as u32;
            Local {
                hour,
                weekday: Weekday { num_days_from_monday: weekday },
            }
        }

        pub fn hour(&self) -> u8 {
            self.hour as u8
        }

        pub fn weekday(&self) -> &Weekday {
            &self.weekday
        }
    }

    impl Weekday {
        pub fn num_days_from_monday(&self) -> u8 {
            self.num_days_from_monday as u8
        }
    }

    pub fn Local() -> Self {
        Self::now()
    }
}