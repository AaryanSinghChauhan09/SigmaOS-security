// SPDX-License-Identifier: MIT
//! SigmaOS-security — Privilege separation, LSM hooks, CVE auditor, and
//! vulnerability scanner. Inspired by AppArmor, SELinux MAC, and
//! Ubuntu Security Notices patterns.
//!
//! Design principles: single responsibility, fail-fast, no unsafe code,
//! deterministic unit-testable logic.

#![forbid(unsafe_code)]

use std::{fmt, collections::HashMap};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    InvalidCveId(String),
    InvalidCvssScore(String),
    PolicyNotFound(String),
    SubjectNotRegistered(String),
    PermissionDenied { subject: String, object: String, action: String },
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCveId(s) => write!(f, "invalid CVE ID: {s}"),
            Self::InvalidCvssScore(s) => write!(f, "invalid CVSS score: {s}"),
            Self::PolicyNotFound(s) => write!(f, "policy not found: {s}"),
            Self::SubjectNotRegistered(s) => write!(f, "subject not registered: {s}"),
            Self::PermissionDenied { subject, object, action } =>
                write!(f, "permission denied: {subject} → {action} → {object}"),
        }
    }
}

impl std::error::Error for SecurityError {}

// ── CVE / Vulnerability scanner ───────────────────────────────────────────────

/// CVSS severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None,     // 0.0
    Low,      // 0.1-3.9
    Medium,   // 4.0-6.9
    High,     // 7.0-8.9
    Critical, // 9.0-10.0
}

impl Severity {
    pub fn from_score(score: f32) -> Self {
        if score <= 0.0       { Self::None }
        else if score < 4.0   { Self::Low }
        else if score < 7.0   { Self::Medium }
        else if score < 9.0   { Self::High }
        else                  { Self::Critical }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None     => "None",
            Self::Low      => "Low",
            Self::Medium   => "Medium",
            Self::High     => "High",
            Self::Critical => "Critical",
        })
    }
}

/// A known CVE entry.
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub cve_id:           String,
    pub affected_package: String,
    pub affected_version: String,
    pub cvss_score:       f32,
    pub severity:         Severity,
    pub description:      String,
    pub fixed_in:         Option<String>,
}

impl Vulnerability {
    /// Create a new vulnerability entry. CVE ID must match CVE-YYYY-NNNNN format.
    pub fn new(
        cve_id:           impl Into<String>,
        affected_package: impl Into<String>,
        affected_version: impl Into<String>,
        cvss_score:       f32,
        description:      impl Into<String>,
    ) -> Result<Self, SecurityError> {
        let cve_id = cve_id.into();
        if !is_valid_cve(&cve_id) {
            return Err(SecurityError::InvalidCveId(cve_id));
        }
        if !(0.0..=10.0).contains(&cvss_score) {
            return Err(SecurityError::InvalidCvssScore(cvss_score.to_string()));
        }
        let severity = Severity::from_score(cvss_score);
        Ok(Self {
            cve_id,
            affected_package: affected_package.into(),
            affected_version: affected_version.into(),
            cvss_score,
            severity,
            description: description.into(),
            fixed_in: None,
        })
    }

    pub fn with_fix(mut self, version: impl Into<String>) -> Self {
        self.fixed_in = Some(version.into());
        self
    }

    pub fn is_fixed(&self) -> bool { self.fixed_in.is_some() }
}

fn is_valid_cve(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() < 3 { return false; }
    if parts[0] != "CVE" { return false; }
    parts[1].parse::<u16>().is_ok() && parts[2].parse::<u32>().is_ok()
}

/// CVE database / vulnerability scanner.
#[derive(Debug, Default)]
pub struct SecurityAuditor {
    vulnerabilities: Vec<Vulnerability>,
}

impl SecurityAuditor {
    pub fn new() -> Self { Self::default() }

    pub fn register(&mut self, vuln: Vulnerability) {
        self.vulnerabilities.push(vuln);
    }

    /// Find all vulnerabilities affecting a package.
    pub fn audit_package(&self, package: &str) -> Vec<&Vulnerability> {
        self.vulnerabilities.iter()
            .filter(|v| v.affected_package == package)
            .collect()
    }

    /// Return all unpatched (no fix version) vulnerabilities at or above severity.
    pub fn unpatched_at_severity(&self, min: Severity) -> Vec<&Vulnerability> {
        self.vulnerabilities.iter()
            .filter(|v| !v.is_fixed() && v.severity >= min)
            .collect()
    }

    /// Total vulnerability count.
    pub fn count(&self) -> usize { self.vulnerabilities.len() }

    /// Count by severity.
    pub fn count_by_severity(&self, sev: Severity) -> usize {
        self.vulnerabilities.iter().filter(|v| v.severity == sev).count()
    }
}

// ── MAC (Mandatory Access Control) ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Read,
    Write,
    Execute,
    NetworkConnect,
    FileCreate,
    FileDelete,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read          => "read",
            Self::Write         => "write",
            Self::Execute       => "execute",
            Self::NetworkConnect => "network_connect",
            Self::FileCreate    => "file_create",
            Self::FileDelete    => "file_delete",
        })
    }
}

/// A policy rule: allow or deny a (subject, object, action) triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Allow { object_prefix: String, action: Action },
    Deny  { object_prefix: String, action: Action },
}

/// MAC policy for a named subject (process / domain).
#[derive(Debug, Clone)]
pub struct SubjectPolicy {
    pub subject: String,
    rules:       Vec<Rule>,
}

impl SubjectPolicy {
    pub fn new(subject: impl Into<String>) -> Self {
        Self { subject: subject.into(), rules: Vec::new() }
    }

    pub fn allow(mut self, object_prefix: impl Into<String>, action: Action) -> Self {
        self.rules.push(Rule::Allow { object_prefix: object_prefix.into(), action });
        self
    }

    pub fn deny(mut self, object_prefix: impl Into<String>, action: Action) -> Self {
        self.rules.push(Rule::Deny { object_prefix: object_prefix.into(), action });
        self
    }

    /// Check whether this subject may perform `action` on `object`.
    /// Deny rules take priority over allow rules.
    pub fn check(&self, object: &str, action: &Action) -> bool {
        let mut permitted = false;
        for rule in &self.rules {
            match rule {
                Rule::Deny { object_prefix, action: a } if a == action
                    && object.starts_with(object_prefix.as_str()) => { return false; }
                Rule::Allow { object_prefix, action: a } if a == action
                    && object.starts_with(object_prefix.as_str()) => { permitted = true; }
                _ => {}
            }
        }
        permitted
    }
}

/// LSM-style policy enforcement point.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    policies: HashMap<String, SubjectPolicy>,
}

impl PolicyEngine {
    pub fn new() -> Self { Self::default() }

    pub fn register_policy(&mut self, policy: SubjectPolicy) {
        self.policies.insert(policy.subject.clone(), policy);
    }

    /// Enforce a MAC check. Returns Ok(()) if permitted, Err if denied or unknown.
    pub fn enforce(&self, subject: &str, object: &str, action: Action)
        -> Result<(), SecurityError> {
        let policy = self.policies.get(subject)
            .ok_or_else(|| SecurityError::SubjectNotRegistered(subject.to_string()))?;
        if policy.check(object, &action) {
            Ok(())
        } else {
            Err(SecurityError::PermissionDenied {
                subject: subject.to_string(),
                object:  object.to_string(),
                action:  action.to_string(),
            })
        }
    }

    pub fn subject_count(&self) -> usize { self.policies.len() }
}

// ── Privilege separation ──────────────────────────────────────────────────────

/// Capability bits (Linux-inspired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    NetAdmin,
    SysAdmin,
    Chown,
    Kill,
    Setuid,
    DacOverride,
}

/// A privilege-separated process descriptor.
#[derive(Debug, Clone)]
pub struct ProcessPrivileges {
    pub uid:           u32,
    pub gid:           u32,
    capabilities:      std::collections::HashSet<Capability>,
    no_new_privs:      bool,
}

impl ProcessPrivileges {
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid, capabilities: Default::default(), no_new_privs: false }
    }

    pub fn with_cap(mut self, cap: Capability) -> Self {
        self.capabilities.insert(cap);
        self
    }

    pub fn set_no_new_privs(mut self) -> Self {
        self.no_new_privs = true;
        self
    }

    pub fn has_cap(&self, cap: Capability) -> bool { self.capabilities.contains(&cap) }
    pub fn is_no_new_privs(&self) -> bool { self.no_new_privs }
    pub fn is_root(&self) -> bool { self.uid == 0 }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cve(id: &str, pkg: &str, score: f32) -> Vulnerability {
        Vulnerability::new(id, pkg, "1.0.0", score, "test vuln").unwrap()
    }

    #[test]
    fn test_severity_classification() {
        assert_eq!(Severity::from_score(0.0),  Severity::None);
        assert_eq!(Severity::from_score(3.9),  Severity::Low);
        assert_eq!(Severity::from_score(6.9),  Severity::Medium);
        assert_eq!(Severity::from_score(8.9),  Severity::High);
        assert_eq!(Severity::from_score(9.5),  Severity::Critical);
        assert_eq!(Severity::from_score(10.0), Severity::Critical);
    }

    #[test]
    fn test_cve_id_validation() {
        assert!(Vulnerability::new("CVE-2026-1234", "pkg", "1.0", 7.0, "d").is_ok());
        assert!(Vulnerability::new("CVE-99-99999",  "pkg", "1.0", 7.0, "d").is_ok());
        assert!(Vulnerability::new("INVALID", "pkg", "1.0", 7.0, "d").is_err());
        assert!(Vulnerability::new("CVE-XXXX-YY", "pkg", "1.0", 7.0, "d").is_err());
    }

    #[test]
    fn test_cvss_out_of_range() {
        assert!(Vulnerability::new("CVE-2026-1", "p", "1", -0.1, "d").is_err());
        assert!(Vulnerability::new("CVE-2026-1", "p", "1", 10.1, "d").is_err());
    }

    #[test]
    fn test_audit_package() {
        let mut auditor = SecurityAuditor::new();
        auditor.register(make_cve("CVE-2026-100", "openssl", 9.1));
        auditor.register(make_cve("CVE-2026-101", "curl",    5.5));
        auditor.register(make_cve("CVE-2026-102", "openssl", 7.2));
        let results = auditor.audit_package("openssl");
        assert_eq!(results.len(), 2);
        assert_eq!(auditor.audit_package("curl").len(), 1);
        assert_eq!(auditor.audit_package("rustc").len(), 0);
    }

    #[test]
    fn test_unpatched_severity_filter() {
        let mut auditor = SecurityAuditor::new();
        auditor.register(make_cve("CVE-2026-200", "pkg", 9.0)); // critical, unpatched
        let mut fixed = make_cve("CVE-2026-201", "pkg", 9.0);
        fixed.fixed_in = Some("1.1.0".into());
        auditor.register(fixed);
        auditor.register(make_cve("CVE-2026-202", "pkg", 3.0)); // low
        let criticals = auditor.unpatched_at_severity(Severity::Critical);
        assert_eq!(criticals.len(), 1);
        assert_eq!(criticals[0].cve_id, "CVE-2026-200");
    }

    #[test]
    fn test_mac_allow_deny() {
        let policy = SubjectPolicy::new("firefox")
            .allow("/home/user/Downloads", Action::Read)
            .allow("/home/user/Downloads", Action::Write)
            .deny("/etc", Action::Write);

        assert!(policy.check("/home/user/Downloads/file.pdf", &Action::Read));
        assert!(policy.check("/home/user/Downloads/out.txt", &Action::Write));
        assert!(!policy.check("/etc/passwd", &Action::Write));
        assert!(!policy.check("/usr/bin", &Action::Execute)); // no rule → deny
    }

    #[test]
    fn test_mac_deny_takes_priority() {
        // Even if there's an allow, a matching deny wins
        let policy = SubjectPolicy::new("app")
            .allow("/data", Action::Read)
            .deny("/data/secret", Action::Read);
        assert!(policy.check("/data/public", &Action::Read));
        assert!(!policy.check("/data/secret/key", &Action::Read));
    }

    #[test]
    fn test_policy_engine_enforce() {
        let mut engine = PolicyEngine::new();
        let policy = SubjectPolicy::new("browser")
            .allow("/tmp", Action::Write);
        engine.register_policy(policy);

        assert!(engine.enforce("browser", "/tmp/cache", Action::Write).is_ok());
        assert!(engine.enforce("browser", "/etc/shadow", Action::Write).is_err());
    }

    #[test]
    fn test_policy_engine_unregistered_subject() {
        let engine = PolicyEngine::new();
        assert!(matches!(
            engine.enforce("unknown_process", "/tmp", Action::Read),
            Err(SecurityError::SubjectNotRegistered(_))
        ));
    }

    #[test]
    fn test_process_privileges() {
        let proc = ProcessPrivileges::new(1000, 1000)
            .with_cap(Capability::NetAdmin)
            .set_no_new_privs();
        assert!(proc.has_cap(Capability::NetAdmin));
        assert!(!proc.has_cap(Capability::SysAdmin));
        assert!(proc.is_no_new_privs());
        assert!(!proc.is_root());

        let root = ProcessPrivileges::new(0, 0).with_cap(Capability::SysAdmin);
        assert!(root.is_root());
        assert!(root.has_cap(Capability::SysAdmin));
    }
}
