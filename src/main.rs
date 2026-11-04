mod config;
mod error;
mod service;
mod crypto;
mod auth;
mod audit;

use config::Config;
use service::Service;
use crypto::CryptoKey;
use auth::AuthManager;
use audit::AuditLogger;
use anyhow::Result;

fn main() -> Result<()> {
    env_logger::init();
    
    let config = Config::default();
    let mut service = Service::new(config);
    
    service.start()?;
    println!("Service started successfully");
    
    // Demonstrate cryptographic operations
    let key = CryptoKey::new(vec![1, 2, 3, 4, 5]);
    println!("Key secure: {}", key.is_secure());
    println!("Key data: {:?}", key.data());
    
    // Demonstrate authentication
    let mut auth = AuthManager::new();
    auth.register("user".to_string(), vec![1, 2, 3], vec![4, 5, 6])?;
    let token = auth.authenticate("user", &[1, 2, 3])?;
    println!("Authenticated with token: {}", token);
    
    // Demonstrate audit logging
    let logger = AuditLogger::new("/tmp/audit.log".to_string());
    let event = logger.auth_event("user", "LOGIN", "SUCCESS");
    println!("Audit event created: {}", event.event_type);
    
    service.stop()?;
    println!("Service stopped successfully");
    
    Ok(())
}
