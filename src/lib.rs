pub mod auth;
pub mod config;
pub mod error;
pub mod service;

pub use auth::{AuthResult, Authenticator};
pub use config::Config;
pub use error::{ComponentError, Result};
pub use service::{Service, ServiceStatus};

pub trait Component {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn initialize(&mut self) -> error::Result<()>;
    fn shutdown(&mut self) -> error::Result<()>;
    fn health_check(&self) -> error::Result<()>;
}

pub struct SecurityComponent {
    service: service::Service,
}

impl SecurityComponent {
    pub fn new(config: Config) -> Self {
        Self { service: service::Service::new(config) }
    }
}

impl Component for SecurityComponent {
    fn name(&self) -> &str { "sigmaos-security" }
    fn version(&self) -> &str { env!("CARGO_PKG_VERSION") }

    fn initialize(&mut self) -> error::Result<()> {
        self.service.start()
    }

    fn shutdown(&mut self) -> error::Result<()> {
        self.service.stop()
    }

    fn health_check(&self) -> error::Result<()> {
        if self.service.is_running() {
            Ok(())
        } else {
            Err(error::ComponentError::Service("security service not running".to_string()))
        }
    }
}
