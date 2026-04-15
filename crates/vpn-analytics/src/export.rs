use crate::{events::EventRecorder, metrics::MetricsRecorder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExportFormat {
    Prometheus,
    Json,
    Csv,
}

pub struct PrometheusExporter {
    metrics: Arc<MetricsRecorder>,
    events: Arc<EventRecorder>,
}

impl PrometheusExporter {
    pub fn new(metrics: Arc<MetricsRecorder>, events: Arc<EventRecorder>) -> Self {
        Self { metrics, events }
    }

    fn get_bandwidth(&self) -> Option<crate::metrics::BandwidthMetrics> {
        Some(self.metrics.bandwidth().current())
    }

    pub fn export(&self) -> String {
        let mut output = String::new();

        let summary = self.metrics.summary();
        let active = &summary.active_session;

        output.push_str("# HELP aegis_connected Whether currently connected (1=yes, 0=no)\n");
        output.push_str(&format!(
            "# TYPE aegis_connected gauge\n"
        ));
        output.push_str(&format!(
            "aegis_connected {}\n",
            if active.status == crate::metrics::ConnectionStatus::Connected {
                1
            } else {
                0
            }
        ));

        output.push_str("\n# HELP aegis_session_duration_seconds Current session duration in seconds\n");
        output.push_str("# TYPE aegis_session_duration_seconds gauge\n");
        output.push_str(&format!(
            "aegis_session_duration_seconds {}\n",
            active.duration_secs
        ));

        output.push_str("\n# HELP aegis_bytes_sent_total Total bytes sent in current session\n");
        output.push_str("# TYPE aegis_bytes_sent_total counter\n");
        output.push_str(&format!("aegis_bytes_sent_total {}\n", active.bytes_sent));

        output.push_str("\n# HELP aegis_bytes_received_total Total bytes received in current session\n");
        output.push_str("# TYPE aegis_bytes_received_total counter\n");
        output.push_str(&format!(
            "aegis_bytes_received_total {}\n",
            active.bytes_received
        ));

        output.push_str("\n# HELP aegis_packets_sent_total Total packets sent in current session\n");
        output.push_str("# TYPE aegis_packets_sent_total counter\n");
        output.push_str(&format!(
            "aegis_packets_sent_total {}\n",
            active.packets_sent
        ));

        output.push_str("\n# HELP aegis_packets_received_total Total packets received in current session\n");
        output.push_str("# TYPE aegis_packets_received_total counter\n");
        output.push_str(&format!(
            "aegis_packets_received_total {}\n",
            active.packets_received
        ));

        output.push_str("\n# HELP aegis_latency_ms Current latency to server in milliseconds\n");
        output.push_str("# TYPE aegis_latency_ms gauge\n");
        output.push_str(&format!(
            "aegis_latency_ms {}\n",
            active.latency_ms.unwrap_or(0)
        ));

        output.push_str("\n# HELP aegis_handshake_duration_ms Handshake duration in milliseconds\n");
        output.push_str("# TYPE aegis_handshake_duration_ms gauge\n");
        output.push_str(&format!(
            "aegis_handshake_duration_ms {}\n",
            active.handshake_duration_ms.unwrap_or(0)
        ));

        output.push_str("\n# HELP aegis_reconnection_count Number of reconnections in current session\n");
        output.push_str("# TYPE aegis_reconnection_count counter\n");
        output.push_str(&format!(
            "aegis_reconnection_count {}\n",
            active.reconnection_count
        ));

        output.push_str("\n# HELP aegis_total_sessions Total number of historical sessions\n");
        output.push_str("# TYPE aegis_total_sessions gauge\n");
        output.push_str(&format!("aegis_total_sessions {}\n", summary.total_sessions));

        output.push_str("\n# HELP aegis_successful_sessions Total number of successful sessions\n");
        output.push_str("# TYPE aegis_successful_sessions gauge\n");
        output.push_str(&format!(
            "aegis_successful_sessions {}\n",
            summary.successful_sessions
        ));

        output.push_str("\n# HELP aegis_session_success_rate Percentage of successful sessions\n");
        output.push_str("# TYPE aegis_session_success_rate gauge\n");
        output.push_str(&format!(
            "aegis_session_success_rate {}\n",
            summary.success_rate
        ));

        output.push_str("\n# HELP aegis_server_count Number of unique servers used\n");
        output.push_str("# TYPE aegis_server_count gauge\n");
        output.push_str(&format!("aegis_server_count {}\n", summary.server_count));

        if let Some(bw) = self.get_bandwidth() {
            output.push_str("\n# HELP aegis_bandwidth_upload_bytes_per_second Current upload speed in Bps\n");
            output.push_str("# TYPE aegis_bandwidth_upload_bytes_per_second gauge\n");
            output.push_str(&format!("aegis_bandwidth_upload_bytes_per_second {}\n", bw.upload_speed_bps));

            output.push_str("\n# HELP aegis_bandwidth_download_bytes_per_second Current download speed in Bps\n");
            output.push_str("# TYPE aegis_bandwidth_download_bytes_per_second gauge\n");
            output.push_str(&format!(
                "aegis_bandwidth_download_bytes_per_second {}\n",
                bw.download_speed_bps
            ));

            output.push_str("\n# HELP aegis_bandwidth_peak_upload_bytes_per_second Peak upload speed in Bps\n");
            output.push_str("# TYPE aegis_bandwidth_peak_upload_bytes_per_second gauge\n");
            output.push_str(&format!(
                "aegis_bandwidth_peak_upload_bytes_per_second {}\n",
                bw.peak_upload_bps
            ));

            output.push_str("\n# HELP aegis_bandwidth_peak_download_bytes_per_second Peak download speed in Bps\n");
            output.push_str("# TYPE aegis_bandwidth_peak_download_bytes_per_second gauge\n");
            output.push_str(&format!(
                "aegis_bandwidth_peak_download_bytes_per_second {}\n",
                bw.peak_download_bps
            ));

            output.push_str("\n# HELP aegis_bandwidth_avg_upload_bytes_per_second Average upload speed in Bps\n");
            output.push_str("# TYPE aegis_bandwidth_avg_upload_bytes_per_second gauge\n");
            output.push_str(&format!(
                "aegis_bandwidth_avg_upload_bytes_per_second {}\n",
                bw.avg_upload_bps
            ));

            output.push_str("\n# HELP aegis_bandwidth_avg_download_bytes_per_second Average download speed in Bps\n");
            output.push_str("# TYPE aegis_bandwidth_avg_download_bytes_per_second gauge\n");
            output.push_str(&format!(
                "aegis_bandwidth_avg_download_bytes_per_second {}\n",
                bw.avg_download_bps
            ));

            output.push_str("\n# HELP aegis_bandwidth_total_megabytes Total data transferred in MB\n");
            output.push_str("# TYPE aegis_bandwidth_total_megabytes gauge\n");
            output.push_str(&format!("aegis_bandwidth_total_megabytes {}\n", bw.total_transfer_mb));
        }

        for server_stat in self.metrics.server_stats() {
            let server_label = sanitize_label(&server_stat.server);
            
            output.push_str(&format!(
                "\n# HELP aegis_server_connections_total Connections to server {}\n",
                server_stat.server
            ));
            output.push_str("# TYPE aegis_server_connections_total counter\n");
            output.push_str(&format!(
                "aegis_server_connections_total{{server=\"{}\"}} {}\n",
                server_label, server_stat.total_connections
            ));

            output.push_str(&format!(
                "\n# HELP aegis_server_avg_latency_ms Average latency to server {}\n",
                server_stat.server
            ));
            output.push_str("# TYPE aegis_server_avg_latency_ms gauge\n");
            output.push_str(&format!(
                "aegis_server_avg_latency_ms{{server=\"{}\"}} {}\n",
                server_label, server_stat.avg_latency_ms
            ));

            output.push_str(&format!(
                "\n# HELP aegis_server_avg_handshake_ms Average handshake time to server {}\n",
                server_stat.server
            ));
            output.push_str("# TYPE aegis_server_avg_handshake_ms gauge\n");
            output.push_str(&format!(
                "aegis_server_avg_handshake_ms{{server=\"{}\"}} {}\n",
                server_label, server_stat.avg_handshake_ms
            ));
        }

        output
    }

    pub fn export_json(&self) -> serde_json::Value {
        let summary = self.metrics.summary();
        let events: Vec<_> = self.events.events().iter().map(|e| {
            serde_json::json!({
                "id": e.id,
                "type": e.event_type.to_string(),
                "session_id": e.session_id,
                "server": e.server,
                "timestamp": e.timestamp,
                "duration_ms": e.duration_ms,
            })
        }).collect();

        let bw = self.get_bandwidth();

        serde_json::json!({
            "active_session": summary.active_session,
            "summary": {
                "total_sessions": summary.total_sessions,
                "successful_sessions": summary.successful_sessions,
                "total_bytes_sent": summary.total_bytes_sent,
                "total_bytes_received": summary.total_bytes_received,
                "total_duration_secs": summary.total_duration_secs,
                "success_rate": summary.success_rate,
                "server_count": summary.server_count,
            },
            "bandwidth": bw,
            "server_stats": self.metrics.server_stats(),
            "recent_events": events,
        })
    }

    pub fn format(&self, format: ExportFormat) -> Result<String, String> {
        match format {
            ExportFormat::Prometheus => Ok(self.export()),
            ExportFormat::Json => serde_json::to_string_pretty(&self.export_json())
                .map_err(|e| e.to_string()),
            ExportFormat::Csv => self.export_csv(),
        }
    }

    pub fn export_csv(&self) -> Result<String, String> {
        let summary = self.metrics.summary();
        let mut output = String::new();

        output.push_str("metric,value\n");
        output.push_str(&format!("session_id,{}\n", summary.active_session.session_id));
        output.push_str(&format!("server,{}\n", summary.active_session.server));
        output.push_str(&format!("status,{}\n", summary.active_session.status));
        output.push_str(&format!("duration_seconds,{}\n", summary.active_session.duration_secs));
        output.push_str(&format!("bytes_sent,{}\n", summary.active_session.bytes_sent));
        output.push_str(&format!("bytes_received,{}\n", summary.active_session.bytes_received));
        output.push_str(&format!("packets_sent,{}\n", summary.active_session.packets_sent));
        output.push_str(&format!("packets_received,{}\n", summary.active_session.packets_received));

        if let Some(bw) = self.get_bandwidth() {
            output.push_str(&format!("upload_speed_bps,{}\n", bw.upload_speed_bps));
            output.push_str(&format!("download_speed_bps,{}\n", bw.download_speed_bps));
            output.push_str(&format!("peak_upload_bps,{}\n", bw.peak_upload_bps));
            output.push_str(&format!("peak_download_bps,{}\n", bw.peak_download_bps));
            output.push_str(&format!("avg_upload_bps,{}\n", bw.avg_upload_bps));
            output.push_str(&format!("avg_download_bps,{}\n", bw.avg_download_bps));
            output.push_str(&format!("total_transfer_mb,{}\n", bw.total_transfer_mb));
        }

        output.push_str("\nsummary\n");
        output.push_str(&format!("total_sessions,{}\n", summary.total_sessions));
        output.push_str(&format!("successful_sessions,{}\n", summary.successful_sessions));
        output.push_str(&format!("total_duration_secs,{}\n", summary.total_duration_secs));
        output.push_str(&format!("success_rate,{}\n", summary.success_rate));
        output.push_str(&format!("server_count,{}\n", summary.server_count));

        Ok(output)
    }
}

fn sanitize_label(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => "_".to_string(),
            '\\' => "_".to_string(),
            '\n' => "_".to_string(),
            _ => c.to_string(),
        })
        .collect()
}