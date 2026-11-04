//! Audit logging for security events
//! Follows: Audit Trail, Compliance, Transparency

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Audit event
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub user: String,
    pub resource: String,
    pub action: String,
    pub result: String,
}

/// Audit logger
pub struct AuditLogger {
    log_file: String,
}

impl AuditLogger {
    pub fn new(log_file: String) -> Self {
        AuditLogger { log_file }
    }

    /// Log audit event
    pub fn log(&self, event: AuditEvent) -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;
        
        let log_entry = format!(
            "[{}] {} - {} - {} - {} - {}\n",
            event.timestamp,
            event.event_type,
            event.user,
            event.resource,
            event.action,
            event.result
        );
        
        file.write_all(log_entry.as_bytes())?;
        file.flush()?;
        log::debug!("Audit event logged");
        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create authentication event
    pub fn auth_event(&self, user: &str, action: &str, result: &str) -> AuditEvent {
        AuditEvent {
            timestamp: Self::current_timestamp(),
            event_type: "AUTHENTICATION".to_string(),
            user: user.to_string(),
            resource: "SYSTEM".to_string(),
            action: action.to_string(),
            result: result.to_string(),
        }
    }

    /// Create access event
    pub fn access_event(&self, user: &str, resource: &str, action: &str, result: &str) -> AuditEvent {
        AuditEvent {
            timestamp: Self::current_timestamp(),
            event_type: "ACCESS".to_string(),
            user: user.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            result: result.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logging() {
        let logger = AuditLogger::new("/tmp/test_audit.log".to_string());
        let event = logger.auth_event("testuser", "LOGIN", "SUCCESS");
        assert_eq!(event.event_type, "AUTHENTICATION");
        assert!(event.timestamp > 0);
    }
}
