use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    Granted,
    Denied(String),
}

pub struct Authenticator {
    sessions: HashMap<String, bool>,
}

impl Authenticator {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn authenticate(&mut self, user: &str, _cred: &str) -> AuthResult {
        if !user.is_empty() {
            self.sessions.insert(user.to_string(), true);
            AuthResult::Granted
        } else {
            AuthResult::Denied("empty username".to_string())
        }
    }

    pub fn is_authenticated(&self, user: &str) -> bool {
        self.sessions.get(user).copied().unwrap_or(false)
    }

    pub fn logout(&mut self, user: &str) {
        self.sessions.remove(user);
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.values().filter(|&&v| v).count()
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}
