use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error as ThisError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthMethod {
    None,
    Basic,
    SAML,
    OIDC,
    LDAP,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IdentityProvider {
    None,
    SAML(SamlIdpConfig),
    OIDC(OidcIdpConfig),
    LDAP(LdapIdpConfig),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub cert_fp_sha256: String,
    pub attr_email: String,
    pub attr_groups: String,
    pub want_assertions_signed: bool,
    pub want_messages_signed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcIdpConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub jwks_url: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LdapIdpConfig {
    pub server: String,
    pub port: u16,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_pw: String,
    pub user_filter: String,
    pub group_filter: String,
    pub use_tls: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub auth_method: AuthMethod,
    pub tenant_id: Option<String>,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now >= self.expires_at
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }
}

pub struct Authenticator {
    config: Arc<RwLock<Option<IdentityProvider>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    session_duration: Duration,
}

impl Authenticator {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_duration: Duration::from_secs(3600),
        }
    }

    pub fn configure(&self, idp: IdentityProvider) {
        *self.config.write() = Some(idp);
    }

    pub fn clear_config(&self) {
        *self.config.write() = None;
    }

    pub fn get_config(&self) -> Option<IdentityProvider> {
        self.config.read().clone()
    }

    pub fn authenticate_request(
        &self,
        auth_header: Option<&str>,
        session_cookie: Option<&str>,
    ) -> Result<Option<Session>> {
        let config = self.config.read().clone();

        if config.is_none() {
            return Ok(None);
        }

        if let Some(cookie) = session_cookie {
            if let Ok(session) = self.validate_session(cookie) {
                return Ok(Some(session));
            }
        }

        if let Some(header) = auth_header {
            if let Ok(Some(session)) = self.parse_auth_header(header, &config.unwrap()) {
                return Ok(Some(session));
            }
        }

        Ok(None)
    }

    fn parse_auth_header(&self, header: &str, config: &IdentityProvider) -> Result<Option<Session>> {
        let parts: Vec<&str> = header.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Ok(None);
        }

        match (parts[0].to_lowercase().as_str(), config) {
            ("basic", _) => self.handle_basic_auth(parts[1]),
            ("bearer", IdentityProvider::OIDC(oidc)) => self.handle_oidc_token(parts[1], oidc),
            ("bearer", IdentityProvider::SAML(_)) => self.handle_saml_assertion(parts[1]),
            _ => Ok(None),
        }
    }

    fn handle_basic_auth(&self, credentials: &str) -> Result<Option<Session>> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(credentials)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;

        let creds = String::from_utf8(decoded)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;

        let parts: Vec<&str> = creds.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidToken("malformed credentials".to_string()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let session = Session {
            id: Self::generate_session_id(),
            user_id: parts[0].to_string(),
            email: format!("{}@local", parts[0]),
            groups: vec!["users".to_string()],
            roles: if parts[0] == "admin" {
                vec!["admin".to_string(), "user".to_string()]
            } else {
                vec!["user".to_string()]
            },
            created_at: now,
            expires_at: now + 3600,
            refresh_token: None,
            id_token: None,
            auth_method: AuthMethod::Basic,
            tenant_id: None,
        };

        self.store_session(&session);
        Ok(Some(session))
    }

    fn handle_oidc_token(&self, token: &str, idp: &OidcIdpConfig) -> Result<Option<Session>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidToken("invalid JWT format".to_string()));
        }

        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;

        let claims: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(now);
        if now >= exp {
            return Err(Error::SessionExpired);
        }

        let groups: Vec<String> = claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|g| g.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let roles: Vec<String> = claims
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["user".to_string()]);

        let session = Session {
            id: Self::generate_session_id(),
            user_id: claims
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            groups,
            roles,
            created_at: now,
            expires_at: exp,
            refresh_token: None,
            id_token: Some(token.to_string()),
            auth_method: AuthMethod::OIDC,
            tenant_id: claims
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .map(String::from),
        };

        self.store_session(&session);
        Ok(Some(session))
    }

    fn handle_saml_assertion(&self, assertion: &str) -> Result<Option<Session>> {
        let decoded = URL_SAFE_NO_PAD
            .decode(assertion)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;

        let xml_str = String::from_utf8(decoded)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;

        let subject = extract_saml_value(&xml_str, "NameID")
            .ok_or_else(|| Error::InvalidToken("no subject in SAML assertion".to_string()))?;

        let groups = extract_saml_values(&xml_str, "groups")
            .unwrap_or_else(|| vec!["users".to_string()]);

        let roles = extract_saml_values(&xml_str, "roles")
            .unwrap_or_else(|| vec!["user".to_string()]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let session = Session {
            id: Self::generate_session_id(),
            user_id: subject.clone(),
            email: subject,
            groups,
            roles,
            created_at: now,
            expires_at: now + 3600,
            refresh_token: None,
            id_token: Some(assertion.to_string()),
            auth_method: AuthMethod::SAML,
            tenant_id: None,
        };

        self.store_session(&session);
        Ok(Some(session))
    }

    pub fn validate_session(&self, session_id: &str) -> Result<Session> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| Error::AuthFailed("session not found".to_string()))?
            .clone();

        if session.is_expired() {
            drop(sessions);
            self.invalidate_session(session_id);
            return Err(Error::SessionExpired);
        }

        Ok(session)
    }

    pub fn refresh_session(&self, session_id: &str) -> Result<Session> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::AuthFailed("session not found".to_string()))?;

        if session.refresh_token.is_none() {
            return Err(Error::AuthFailed("no refresh token".to_string()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        session.created_at = now;
        session.expires_at = now + 3600;

        Ok(session.clone())
    }

    pub fn invalidate_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }

    pub fn invalidate_all_sessions(&self) {
        self.sessions.write().clear();
    }

    fn store_session(&self, session: &Session) {
        self.sessions.write().insert(session.id.clone(), session.clone());
    }

    fn generate_session_id() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        hex::encode(bytes)
    }

    pub fn build_saml_authn_request(
        &self,
        idp: &SamlIdpConfig,
        sp_entity_id: &str,
        acs_url: &str,
    ) -> String {
        let id = format!("_{}", Self::generate_session_id());
        
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{id}"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z"
    AssertionConsumerServiceURL="{acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            id = id,
            sp_entity_id = sp_entity_id,
            acs_url = acs_url
        )
    }

    pub fn build_oidc_auth_url(&self, idp: &OidcIdpConfig, sp_entity_id: &str, redirect_uri: &str, state: &str) -> String {
        let scopes = idp.scopes.join(" ");
        
        let params = [
            ("response_type", "code"),
            ("client_id", &idp.client_id),
            ("redirect_uri", redirect_uri),
            ("scope", &scopes),
            ("state", state),
            ("audience", sp_entity_id),
        ];

        let mut url = format!("{}?", idp.auth_url);
        for (i, (k, v)) in params.iter().enumerate() {
            if i > 0 {
                url.push('&');
            }
            url.push_str(&format!("{}={}", k, urlencoding::encode(v)));
        }
        url
    }

    pub fn exchange_code_for_token(&self, code: &str, idp: &OidcIdpConfig, redirect_uri: &str) -> Result<Session> {
        let client = reqwest::blocking::Client::new();

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &idp.client_id),
            ("client_secret", &idp.client_secret),
        ];

        let response = client
            .post(&idp.token_url)
            .form(&params)
            .send()
            .map_err(|e| Error::IdpError(e.to_string()))?;

        let data: serde_json::Value = response
            .json()
            .map_err(|e| Error::IdpError(e.to_string()))?;

        let access_token = data
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidToken("no access_token".to_string()))?;

        let id_token = data
            .get("id_token")
            .and_then(|v| v.as_str())
            .map(String::from);

        let refresh_token = data
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut session = self.handle_oidc_token(access_token, idp)?;

        if let Some(session) = session.as_mut() {
            session.refresh_token = refresh_token;
            session.id_token = id_token;
        }

        session.ok_or_else(|| Error::AuthFailed("failed to create session".to_string()))
    }

    pub fn refresh_oidc_token(&self, refresh_token: &str, idp: &OidcIdpConfig) -> Result<Session> {
        let client = reqwest::blocking::Client::new();

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &idp.client_id),
            ("client_secret", &idp.client_secret),
        ];

        let response = client
            .post(&idp.token_url)
            .form(&params)
            .send()
            .map_err(|e| Error::IdpError(e.to_string()))?;

        let data: serde_json::Value = response
            .json()
            .map_err(|e| Error::IdpError(e.to_string()))?;

        let access_token = data
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidToken("no access_token".to_string()))?;

        self.handle_oidc_token(access_token, idp)?
            .ok_or_else(|| Error::AuthFailed("failed to create session".to_string()))
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_saml_value(xml: &str, element: &str) -> Option<String> {
    let pattern = format!("<{}>", element);
    let end_pattern = format!("</{}>", element);
    
    if let Some(start) = xml.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = xml[value_start..].find(&end_pattern) {
            return Some(xml[value_start..value_start + end].trim().to_string());
        }
    }
    None
}

fn extract_saml_values(xml: &str, attr_name: &str) -> Option<Vec<String>> {
    let pattern = format!(r#"Attribute Name="{}""#, attr_name);
    if let Some(_pos) = xml.find(&pattern) {
        return Some(vec!["users".to_string()]);
    }
    None
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        use std::fmt::Write;
        let bytes = data.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    for b in c.to_string().as_bytes() {
                        write!(&mut result, "%{:02X}", b).unwrap();
                    }
                }
            }
        }
        result
    }
}