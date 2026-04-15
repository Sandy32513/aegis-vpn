use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct GpoManager {
    templates: HashMap<String, GpoTemplate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GpoTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub settings: GpoSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GpoSettings {
    pub vpn_server: String,
    pub vpn_port: u16,
    pub tunnel_mode: String,
    pub kill_switch: bool,
    pub dns_servers: Vec<String>,
    pub excluded_networks: Vec<String>,
    pub allowed_apps: Vec<String>,
    pub blocked_apps: Vec<String>,
}

impl GpoManager {
    pub fn new() -> Self {
        let mut manager = Self {
            templates: HashMap::new(),
        };
        manager.init_templates();
        manager
    }

    fn init_templates(&mut self) {
        let templates = vec![
            ("secure".to_string(), GpoTemplate {
                id: "aegis-secure".to_string(),
                name: "Aegis Secure VPN".to_string(),
                description: "Maximum security with kill switch".to_string(),
                version: "1.0".to_string(),
                settings: GpoSettings {
                    vpn_server: "{{VPN_SERVER}}".to_string(),
                    vpn_port: 443,
                    tunnel_mode: "udp".to_string(),
                    kill_switch: true,
                    dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
                    excluded_networks: vec![],
                    allowed_apps: vec![],
                    blocked_apps: vec![],
                },
            }),
            ("standard".to_string(), GpoTemplate {
                id: "aegis-standard".to_string(),
                name: "Aegis Standard VPN".to_string(),
                description: "Balanced security and performance".to_string(),
                version: "1.0".to_string(),
                settings: GpoSettings {
                    vpn_server: "{{VPN_SERVER}}".to_string(),
                    vpn_port: 443,
                    tunnel_mode: "udp".to_string(),
                    kill_switch: false,
                    dns_servers: vec!["1.1.1.1".to_string()],
                    excluded_networks: vec![],
                    allowed_apps: vec![],
                    blocked_apps: vec![],
                },
            }),
            ("split".to_string(), GpoTemplate {
                id: "aegis-split".to_string(),
                name: "Aegis Split Tunnel".to_string(),
                description: "Split tunnel for internal resources".to_string(),
                version: "1.0".to_string(),
                settings: GpoSettings {
                    vpn_server: "{{VPN_SERVER}}".to_string(),
                    vpn_port: 443,
                    tunnel_mode: "udp".to_string(),
                    kill_switch: false,
                    dns_servers: vec!["1.1.1.1".to_string()],
                    excluded_networks: vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
                    allowed_apps: vec![],
                    blocked_apps: vec![],
                },
            }),
        ];

        for (key, template) in templates {
            self.templates.insert(key, template);
        }
    }

    pub fn get_template(&self, name: &str) -> Option<&GpoTemplate> {
        self.templates.get(name)
    }

    pub fn templates(&self) -> Vec<&GpoTemplate> {
        self.templates.values().collect()
    }

    pub fn export_xml(&self, name: &str, variables: &HashMap<String, String>) -> Option<String> {
        let template = self.templates.get(name)?;

        let mut xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<GPO>
  <Meta>
    <Name>{}</Name>
    <Description>{}</Description>
    <Version>{}</Version>
  </Meta>
  <Settings>
    <VPN>
      <Server>{}</Server>
      <Port>{}</Port>
      <TunnelMode>{}</TunnelMode>
      <KillSwitch>{}</KillSwitch>
      <DNSServers>
"#,
            template.name,
            template.description,
            template.version,
            variables.get("VPN_SERVER").unwrap_or(&template.settings.vpn_server),
            template.settings.vpn_port,
            template.settings.tunnel_mode,
            template.settings.kill_switch
        );

        for dns in &template.settings.dns_servers {
            xml.push_str(&format!("        <Server>{}</Server>\n", dns));
        }

        xml.push_str("      </DNSServers>\n");

        if !template.settings.excluded_networks.is_empty() {
            xml.push_str("      <ExcludedNetworks>\n");
            for network in &template.settings.excluded_networks {
                xml.push_str(&format!("        <Network>{}</Network>\n", network));
            }
            xml.push_str("      </ExcludedNetworks>\n");
        }

        if !template.settings.allowed_apps.is_empty() {
            xml.push_str("      <AllowedApps>\n");
            for app in &template.settings.allowed_apps {
                xml.push_str(&format!("        <App>{}</App>\n", app));
            }
            xml.push_str("      </AllowedApps>\n");
        }

        if !template.settings.blocked_apps.is_empty() {
            xml.push_str("      <BlockedApps>\n");
            for app in &template.settings.blocked_apps {
                xml.push_str(&format!("        <App>{}</App>\n", app));
            }
            xml.push_str("      </BlockedApps>\n");
        }

        xml.push_str("    </VPN>\n  </Settings>\n</GPO>");

        Some(xml)
    }

    pub fn export_ps1(&self, name: &str, variables: &HashMap<String, String>, output_path: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let template = self.templates.get(name).ok_or("Template not found")?;

        let script = format!(
            r#"# Aegis VPN GPO Script
# Generated: {}
# Template: {}

$Config = @{{
    Server = "{}"
    Port = {}
    TunnelMode = "{}"
    KillSwitch = ${}
    DNSServers = @({})
    ExcludedNetworks = @({})
}}

# Create registry entries
$RegPath = "HKLM:\SOFTWARE\AegisVPN"
if (-not (Test-Path $RegPath)) {{
    New-Item -Path $RegPath -Force | Out-Null
}}

Set-ItemProperty -Path $RegPath -Name "Server" -Value $Config.Server
Set-ItemProperty -Path $RegPath -Name "Port" -Value $Config.Port
Set-ItemProperty -Path $RegPath -Name "TunnelMode" -Value $Config.TunnelMode
Set-ItemProperty -Path $RegPath -Name "KillSwitch" -Value ($Config.KillSwitch -as [bool])

Write-Host "GPO Applied: {}" -ForegroundColor Green
"#,
            chrono::Utc::now().to_rfc3339(),
            template.name,
            variables.get("VPN_SERVER").unwrap_or(&template.settings.vpn_server),
            template.settings.vpn_port,
            template.settings.tunnel_mode,
            template.settings.kill_switch,
            template.settings.dns_servers.join("`, `"),
            template.settings.excluded_networks.join("`, `"),
            template.name
        );

        std::fs::write(output_path, script)?;
        Ok(())
    }

    pub fn list_templates(&self) -> Vec<(String, String)> {
        self.templates
            .iter()
            .map(|(k, t)| (k.clone(), t.name.clone()))
            .collect()
    }
}

impl Default for GpoManager {
    fn default() -> Self {
        Self::new()
    }
}

mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> Self {
            Utc
        }
        pub fn to_rfc3339(&self) -> String {
            "2024-01-01T00:00:00Z".to_string()
        }
    }
}