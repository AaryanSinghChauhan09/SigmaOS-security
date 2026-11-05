#[derive(Debug, Clone)]
pub struct SecurityVulnerability {
    pub cve_id: String,
    pub affected_package: String,
    pub cvss_score: f32,
}

#[derive(Debug, Default)]
pub struct SecurityAuditor {
    known_cves: Vec<SecurityVulnerability>,
}

impl SecurityAuditor {
    pub fn new() -> Self { Self::default() }
    pub fn register_cve(&mut self, cve: SecurityVulnerability) { self.known_cves.push(cve); }
    pub fn audit_package(&self, pkg: &str) -> Vec<&SecurityVulnerability> {
        self.known_cves.iter().filter(|c| c.affected_package == pkg).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_security_audit_package() {
        let mut auditor = SecurityAuditor::new();
        auditor.register_cve(SecurityVulnerability {
            cve_id: "CVE-2026-1105".into(),
            affected_package: "openssl".into(),
            cvss_score: 8.5,
        });
        assert_eq!(auditor.audit_package("openssl").len(), 1);
        assert_eq!(auditor.audit_package("rustc").len(), 0);
    }
}
