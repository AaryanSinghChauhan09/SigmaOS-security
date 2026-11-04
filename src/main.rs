use sigmaos_security::{Config, SecurityComponent, Component};

fn main() {
    env_logger::init();
    let config = Config::default();
    let mut component = SecurityComponent::new(config);
    if let Err(e) = component.initialize() {
        eprintln!("Failed to initialize: {}", e);
        std::process::exit(1);
    }
    println!("SigmaOS security running");
    if let Err(e) = component.shutdown() {
        eprintln!("Shutdown error: {}", e);
    }
}
