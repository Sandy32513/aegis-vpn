use crate::{Error, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Role {
    Admin,
    Operator,
    User,
    Viewer,
    Custom(String),
}

impl Role {
    pub fn name(&self) -> &str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::User => "user",
            Role::Viewer => "viewer",
            Role::Custom(name) => name,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => Role::Admin,
            "operator" => Role::Operator,
            "user" => Role::User,
            "viewer" => Role::Viewer,
            other => Role::Custom(other.to_string()),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub roles: Vec<Role>,
    pub groups: Vec<String>,
    pub enabled: bool,
    pub password_hash: Option<String>,
    pub created_at: i64,
    pub last_login: Option<i64>,
    pub tenant_id: Option<String>,
}

impl User {
    pub fn new(username: String, email: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            username,
            email,
            display_name: None,
            roles: vec![Role::User],
            groups: vec![],
            enabled: true,
            password_hash: None,
            created_at: now,
            last_login: None,
            tenant_id: None,
        }
    }

    pub fn add_role(&mut self, role: Role) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    pub fn remove_role(&mut self, role: &Role) {
        self.roles.retain(|r| r != role);
    }

    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, Role::Admin))
    }

    pub fn can_connect(&self) -> bool {
        self.enabled && (self.has_role(&Role::User) || self.has_role(&Role::Operator) || self.is_admin())
    }

    pub fn can_view_logs(&self) -> bool {
        self.enabled && !self.roles.is_empty()
    }

    pub fn can_modify_config(&self) -> bool {
        self.enabled && (self.has_role(&Role::Operator) || self.is_admin())
    }

    pub fn can_manage_users(&self) -> bool {
        self.enabled && self.is_admin()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub roles: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
    pub tenant_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub password: Option<String>,
    pub roles: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

pub struct UserManager {
    users: Arc<RwLock<HashMap<String, User>>>,
    sessions: Arc<RwLock<HashMap<String, String>>>,
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_user(&self, req: CreateUserRequest) -> Result<User> {
        {
            let users = self.users.read();
            for user in users.values() {
                if user.username == req.username {
                    return Err(Error::UserNotFound(format!("user {} already exists", req.username)));
                }
                if user.email == req.email {
                    return Err(Error::UserNotFound(format!("email {} already in use", req.email)));
                }
            }
        }

        let mut user = User::new(req.username, req.email);
        user.tenant_id = req.tenant_id;

        if let Some(roles) = req.roles {
            user.roles = roles.into_iter().map(Role::from_str).collect();
        }

        if let Some(groups) = req.groups {
            user.groups = groups;
        }

        if let Some(password) = req.password {
            user.password_hash = Some(Self::hash_password(&password)?);
        }

        let id = user.id.clone();
        self.users.write().insert(id, user.clone());
        Ok(user)
    }

    pub fn get_user(&self, user_id: &str) -> Result<User> {
        self.users
            .read()
            .get(user_id)
            .cloned()
            .ok_or_else(|| Error::UserNotFound(user_id.to_string()))
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<User> {
        self.users
            .read()
            .values()
            .find(|u| u.username == username)
            .cloned()
            .ok_or_else(|| Error::UserNotFound(username.to_string()))
    }

    pub fn update_user(&self, user_id: &str, req: UpdateUserRequest) -> Result<User> {
        let mut users = self.users.write();
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| Error::UserNotFound(user_id.to_string()))?;

        if let Some(email) = req.email {
            user.email = email;
        }

        if let Some(display_name) = req.display_name {
            user.display_name = Some(display_name);
        }

        if let Some(password) = req.password {
            user.password_hash = Some(Self::hash_password(&password)?);
        }

        if let Some(roles) = req.roles {
            user.roles = roles.into_iter().map(Role::from_str).collect();
        }

        if let Some(groups) = req.groups {
            user.groups = groups;
        }

        if let Some(enabled) = req.enabled {
            user.enabled = enabled;
        }

        Ok(user.clone())
    }

    pub fn delete_user(&self, user_id: &str) -> Result<()> {
        if self.users.write().remove(user_id).is_none() {
            return Err(Error::UserNotFound(user_id.to_string()));
        }
        Ok(())
    }

    pub fn list_users(&self) -> Vec<User> {
        self.users.read().values().cloned().collect()
    }

    pub fn list_users_by_tenant(&self, tenant_id: &str) -> Vec<User> {
        self.users
            .read()
            .values()
            .filter(|u| u.tenant_id.as_deref() == Some(tenant_id))
            .cloned()
            .collect()
    }

    pub fn verify_password(&self, user_id: &str, password: &str) -> Result<bool> {
        let user = self.get_user(user_id)?;
        let hash = user.password_hash.ok_or_else(|| Error::AuthFailed("no password set".to_string()))?;
        Ok(Self::verify_password_hash(password, &hash)?)
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<User> {
        let user = self.get_user_by_username(username)?;

        if !user.enabled {
            return Err(Error::AuthFailed("user account is disabled".to_string()));
        }

        let hash = user.password_hash.ok_or_else(|| Error::AuthFailed("no password set".to_string()))?;

        if !Self::verify_password_hash(password, &hash)? {
            return Err(Error::AuthFailed("invalid password".to_string()));
        }

        let mut users = self.users.write();
        if let Some(user) = users.get_mut(&user.id) {
            user.last_login = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            );
        }

        Ok(user)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn bind_session(&self, user_id: &str, session_id: &str) {
        self.sessions.write().insert(session_id.to_string(), user_id.to_string());
    }

    pub fn unbind_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }

    pub fn get_user_for_session(&self, session_id: &str) -> Option<User> {
        let user_id = self.sessions.read().get(session_id)?.clone();
        self.users.read().get(&user_id).cloned()
    }

    fn hash_password(password: &str) -> Result<String> {
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};

        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();

        let key = &result[..32];
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| Error::AuthFailed(e.to_string()))?;

        mac.update(password.as_bytes());
        let result = mac.finalize();

        Ok(hex::encode(result))
    }

    fn verify_password_hash(password: &str, hash: &str) -> Result<bool> {
        let computed = Self::hash_password(password)?;
        Ok(computed == hash)
    }
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
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