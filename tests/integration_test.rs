use sigmaos_security::{Authenticator, AuthResult, Config, SecurityComponent, Component};

#[test]
fn test_config_default_aaa() {
    let config = Config::default();
    assert!(config.enabled);
    assert_eq!(config.session_timeout_secs, 3600);
}

#[test]
fn test_config_validate_aaa() {
    let config = Config::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_authenticator_grant_aaa() {
    // Arrange
    let mut auth = Authenticator::new();
    // Act
    let result = auth.authenticate("alice", "password123");
    // Assert
    assert_eq!(result, AuthResult::Granted);
    assert!(auth.is_authenticated("alice"));
}

#[test]
fn test_authenticator_deny_empty_user_aaa() {
    // Arrange
    let mut auth = Authenticator::new();
    // Act
    let result = auth.authenticate("", "password");
    // Assert
    assert!(matches!(result, AuthResult::Denied(_)));
}

#[test]
fn test_authenticator_logout_aaa() {
    // Arrange
    let mut auth = Authenticator::new();
    auth.authenticate("bob", "pass");
    assert!(auth.is_authenticated("bob"));
    // Act
    auth.logout("bob");
    // Assert
    assert!(!auth.is_authenticated("bob"));
}

#[test]
fn test_authenticator_session_count_aaa() {
    // Arrange
    let mut auth = Authenticator::new();
    // Act
    auth.authenticate("alice", "pw");
    auth.authenticate("bob", "pw");
    // Assert
    assert_eq!(auth.active_session_count(), 2);
}

#[test]
fn test_component_lifecycle_aaa() {
    // Arrange
    let mut component = SecurityComponent::new(Config::default());
    // Act + Assert
    assert!(component.initialize().is_ok());
    assert!(component.health_check().is_ok());
    assert!(component.shutdown().is_ok());
}

#[test]
fn test_component_name_aaa() {
    let component = SecurityComponent::new(Config::default());
    assert_eq!(component.name(), "sigmaos-security");
}
