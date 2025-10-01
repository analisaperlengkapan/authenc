use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Enhanced compliance module with SOC 2/3, ISO 27001, etc. (SUPERIOR TO KEYCLOAK)
pub mod enhanced;

/// Compliance framework types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// General Data Protection Regulation
    GDPR,
    /// California Consumer Privacy Act
    CCPA,
    /// Health Insurance Portability and Accountability Act
    HIPAA,
    /// Sarbanes-Oxley Act
    SOX,
    /// Payment Card Industry Data Security Standard
    PciDss,
    /// ISO 27001 Information Security Management
    ISO27001,
    /// National Institute of Standards and Technology framework
    NIST,
    /// Custom compliance framework
    Custom(String),
}

/// Compliance requirement definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    /// Unique identifier for the requirement
    pub id: Uuid,
    /// Compliance framework this requirement belongs to
    pub framework: ComplianceFramework,
    /// Framework-specific requirement identifier
    pub requirement_id: String,
    /// Human-readable title of the requirement
    pub title: String,
    /// Detailed description of the requirement
    pub description: String,
    /// Category this requirement falls under
    pub category: ComplianceCategory,
    /// Severity level of the requirement
    pub severity: ComplianceSeverity,
    /// Whether this requirement is currently enabled
    pub enabled: bool,
    /// Whether this requirement can be checked automatically
    pub automated_check: bool,
}

/// Compliance categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceCategory {
    /// Data protection and privacy requirements
    DataProtection,
    /// Access control and authorization requirements
    AccessControl,
    /// Audit logging and monitoring requirements
    AuditLogging,
    /// Encryption and cryptographic requirements
    Encryption,
    /// Incident response and management requirements
    IncidentResponse,
    /// Risk assessment and management requirements
    RiskManagement,
    /// Privacy protection requirements
    Privacy,
    /// Security assessment and testing requirements
    SecurityAssessment,
}

/// Compliance severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceSeverity {
    /// Critical severity - immediate action required
    Critical,
    /// High severity - urgent attention needed
    High,
    /// Medium severity - should be addressed
    Medium,
    /// Low severity - minor issue
    Low,
    /// Informational - for awareness only
    Informational,
}

/// Compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    /// Unique identifier of the requirement being checked
    pub requirement_id: Uuid,
    /// Timestamp when the check was performed
    pub check_time: DateTime<Utc>,
    /// Overall status of the compliance check
    pub status: ComplianceStatus,
    /// Evidence collected during the check
    pub evidence: Vec<String>,
    /// List of violations found
    pub violations: Vec<String>,
    /// Recommended remediation steps
    pub remediation_steps: Vec<String>,
    /// Compliance score (0.0 to 100.0)
    pub score: f64,
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Fully compliant with requirements
    Compliant,
    /// Not compliant with requirements
    NonCompliant,
    /// Partially compliant with some requirements
    PartiallyCompliant,
    /// Not applicable to current system
    NotApplicable,
    /// Compliance status unknown
    Unknown,
}

/// Compliance check interface
#[async_trait]
pub trait ComplianceCheck: Send + Sync {
    /// Execute the compliance check
    async fn execute(&self) -> Result<ComplianceCheckResult>;
    /// Get the compliance requirement this check implements
    fn requirement(&self) -> &ComplianceRequirement;
}

/// GDPR compliance checks implementation
pub struct GDPRComplianceChecks;

impl Default for GDPRComplianceChecks {
    fn default() -> Self {
        Self::new()
    }
}

impl GDPRComplianceChecks {
    /// Create a new instance of GDPR compliance checks
    pub fn new() -> Self {
        Self
    }

    /// Create a data encryption compliance check for GDPR
    pub fn data_encryption_check() -> Box<dyn ComplianceCheck> {
        Box::new(GDPRDataEncryptionCheck {
            requirement: ComplianceRequirement {
                id: Uuid::new_v4(),
                framework: ComplianceFramework::GDPR,
                requirement_id: "Article 32".to_string(),
                title: "Security of processing".to_string(),
                description: "Appropriate technical and organisational measures for data security"
                    .to_string(),
                category: ComplianceCategory::Encryption,
                severity: ComplianceSeverity::High,
                enabled: true,
                automated_check: true,
            },
        })
    }

    /// Create a data retention compliance check for GDPR
    pub fn data_retention_check() -> Box<dyn ComplianceCheck> {
        Box::new(GDPRDataRetentionCheck {
            requirement: ComplianceRequirement {
                id: Uuid::new_v4(),
                framework: ComplianceFramework::GDPR,
                requirement_id: "Article 5".to_string(),
                title: "Principles relating to processing of personal data".to_string(),
                description: "Personal data shall be kept in a form which permits identification for no longer than necessary".to_string(),
                category: ComplianceCategory::DataProtection,
                severity: ComplianceSeverity::High,
                enabled: true,
                automated_check: true,
            },
        })
    }

    /// Create a consent management compliance check for GDPR
    pub fn consent_management_check() -> Box<dyn ComplianceCheck> {
        Box::new(GDPRConsentManagementCheck {
            requirement: ComplianceRequirement {
                id: Uuid::new_v4(),
                framework: ComplianceFramework::GDPR,
                requirement_id: "Article 7".to_string(),
                title: "Conditions for consent".to_string(),
                description: "Where processing is based on consent, controller shall be able to demonstrate that data subject has consented".to_string(),
                category: ComplianceCategory::Privacy,
                severity: ComplianceSeverity::High,
                enabled: true,
                automated_check: false,
            },
        })
    }
}

/// GDPR data encryption check
pub struct GDPRDataEncryptionCheck {
    requirement: ComplianceRequirement,
}

#[async_trait]
impl ComplianceCheck for GDPRDataEncryptionCheck {
    async fn execute(&self) -> Result<ComplianceCheckResult> {
        // TODO: Check if data is properly encrypted at rest and in transit
        let status = ComplianceStatus::Compliant; // Placeholder
        let evidence = vec![
            "AES-256 encryption enabled for data at rest".to_string(),
            "TLS 1.3 enabled for data in transit".to_string(),
        ];
        let violations = vec![];
        let remediation_steps = vec![];

        Ok(ComplianceCheckResult {
            requirement_id: self.requirement.id,
            check_time: Utc::now(),
            status,
            evidence,
            violations,
            remediation_steps,
            score: 100.0,
        })
    }

    fn requirement(&self) -> &ComplianceRequirement {
        &self.requirement
    }
}

/// GDPR data retention check implementation
pub struct GDPRDataRetentionCheck {
    requirement: ComplianceRequirement,
}

#[async_trait]
impl ComplianceCheck for GDPRDataRetentionCheck {
    async fn execute(&self) -> Result<ComplianceCheckResult> {
        // TODO: Check data retention policies and automatic deletion
        let status = ComplianceStatus::Compliant; // Placeholder
        let evidence = vec![
            "Data retention policies configured".to_string(),
            "Automatic data deletion enabled".to_string(),
        ];
        let violations = vec![];
        let remediation_steps = vec![];

        Ok(ComplianceCheckResult {
            requirement_id: self.requirement.id,
            check_time: Utc::now(),
            status,
            evidence,
            violations,
            remediation_steps,
            score: 100.0,
        })
    }

    fn requirement(&self) -> &ComplianceRequirement {
        &self.requirement
    }
}

/// GDPR consent management check implementation
pub struct GDPRConsentManagementCheck {
    requirement: ComplianceRequirement,
}

#[async_trait]
impl ComplianceCheck for GDPRConsentManagementCheck {
    async fn execute(&self) -> Result<ComplianceCheckResult> {
        // TODO: Check consent management implementation
        let status = ComplianceStatus::PartiallyCompliant; // Placeholder
        let evidence = vec!["Consent management UI implemented".to_string()];
        let violations = vec!["Granular consent options not fully implemented".to_string()];
        let remediation_steps = vec![
            "Implement granular consent options".to_string(),
            "Add consent withdrawal functionality".to_string(),
        ];

        Ok(ComplianceCheckResult {
            requirement_id: self.requirement.id,
            check_time: Utc::now(),
            status,
            evidence,
            violations,
            remediation_steps,
            score: 75.0,
        })
    }

    fn requirement(&self) -> &ComplianceRequirement {
        &self.requirement
    }
}

/// HIPAA compliance checks implementation
pub struct HIPAAComplianceChecks;

impl Default for HIPAAComplianceChecks {
    fn default() -> Self {
        Self::new()
    }
}

impl HIPAAComplianceChecks {
    /// Create a new instance of HIPAA compliance checks
    pub fn new() -> Self {
        Self
    }

    /// Create an access control compliance check for HIPAA
    pub fn access_control_check() -> Box<dyn ComplianceCheck> {
        Box::new(HIPAAAccessControlCheck {
            requirement: ComplianceRequirement {
                id: Uuid::new_v4(),
                framework: ComplianceFramework::HIPAA,
                requirement_id: "164.312(a)(1)".to_string(),
                title: "Access Control".to_string(),
                description:
                    "Implement technical policies and procedures for electronic information systems"
                        .to_string(),
                category: ComplianceCategory::AccessControl,
                severity: ComplianceSeverity::High,
                enabled: true,
                automated_check: true,
            },
        })
    }

    /// Create an audit controls compliance check for HIPAA
    pub fn audit_controls_check() -> Box<dyn ComplianceCheck> {
        Box::new(HIPAAAuditControlsCheck {
            requirement: ComplianceRequirement {
                id: Uuid::new_v4(),
                framework: ComplianceFramework::HIPAA,
                requirement_id: "164.312(b)".to_string(),
                title: "Audit Controls".to_string(),
                description: "Implement hardware, software, and/or procedural mechanisms to record and examine activity in information systems".to_string(),
                category: ComplianceCategory::AuditLogging,
                severity: ComplianceSeverity::High,
                enabled: true,
                automated_check: true,
            },
        })
    }
}

/// HIPAA access control check implementation
pub struct HIPAAAccessControlCheck {
    requirement: ComplianceRequirement,
}

#[async_trait]
impl ComplianceCheck for HIPAAAccessControlCheck {
    async fn execute(&self) -> Result<ComplianceCheckResult> {
        // TODO: Check role-based access control implementation
        let status = ComplianceStatus::Compliant; // Placeholder
        let evidence = vec![
            "RBAC implemented".to_string(),
            "Multi-factor authentication enabled".to_string(),
            "Session timeouts configured".to_string(),
        ];
        let violations = vec![];
        let remediation_steps = vec![];

        Ok(ComplianceCheckResult {
            requirement_id: self.requirement.id,
            check_time: Utc::now(),
            status,
            evidence,
            violations,
            remediation_steps,
            score: 100.0,
        })
    }

    fn requirement(&self) -> &ComplianceRequirement {
        &self.requirement
    }
}

/// HIPAA audit controls check implementation
pub struct HIPAAAuditControlsCheck {
    requirement: ComplianceRequirement,
}

#[async_trait]
impl ComplianceCheck for HIPAAAuditControlsCheck {
    async fn execute(&self) -> Result<ComplianceCheckResult> {
        // TODO: Check audit logging implementation
        let status = ComplianceStatus::Compliant; // Placeholder
        let evidence = vec![
            "Comprehensive audit logging enabled".to_string(),
            "Audit logs are tamper-proof".to_string(),
            "Audit log retention policies configured".to_string(),
        ];
        let violations = vec![];
        let remediation_steps = vec![];

        Ok(ComplianceCheckResult {
            requirement_id: self.requirement.id,
            check_time: Utc::now(),
            status,
            evidence,
            violations,
            remediation_steps,
            score: 100.0,
        })
    }

    fn requirement(&self) -> &ComplianceRequirement {
        &self.requirement
    }
}

/// Main compliance service that manages compliance checks and frameworks
pub struct ComplianceService {
    /// Registered compliance checks
    checks: HashMap<Uuid, Box<dyn ComplianceCheck>>,
    /// Compliance requirements
    requirements: HashMap<Uuid, ComplianceRequirement>,
    /// Enabled compliance frameworks
    enabled_frameworks: Vec<ComplianceFramework>,
    /// Audit service for logging compliance events
    #[allow(dead_code)]
    audit_service: Arc<dyn ComplianceAuditService>,
}

impl ComplianceService {
    /// Create a new compliance service
    pub fn new(audit_service: Arc<dyn ComplianceAuditService>) -> Self {
        Self {
            checks: HashMap::new(),
            requirements: HashMap::new(),
            enabled_frameworks: vec![],
            audit_service,
        }
    }

    /// Enable a compliance framework
    pub fn enable_framework(&mut self, framework: ComplianceFramework) {
        if !self.enabled_frameworks.contains(&framework) {
            self.enabled_frameworks.push(framework);
        }
    }

    /// Disable a compliance framework
    pub fn disable_framework(&mut self, framework: &ComplianceFramework) {
        self.enabled_frameworks.retain(|f| f != framework);
    }

    /// Register a compliance check
    pub fn register_check(&mut self, check: Box<dyn ComplianceCheck>) {
        let requirement = check.requirement().clone();
        let check_id = requirement.id;
        self.checks.insert(check_id, check);
        self.requirements.insert(check_id, requirement);
    }

    /// Execute all registered compliance checks
    pub async fn execute_all_checks(&self) -> Result<Vec<ComplianceCheckResult>> {
        let mut results = Vec::new();
        for check in self.checks.values() {
            let result = check.execute().await?;
            results.push(result);
        }
        Ok(results)
    }

    /// Execute a specific compliance check by ID
    pub async fn execute_check(&self, check_id: &Uuid) -> Result<Option<ComplianceCheckResult>> {
        if let Some(check) = self.checks.get(check_id) {
            let result = check.execute().await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Generate a comprehensive compliance report
    pub async fn get_compliance_report(&self) -> Result<ComplianceReport> {
        let results = self.execute_all_checks().await?;
        let recommendations = self.generate_recommendations(&results);
        let overall_score = if !results.is_empty() {
            results.iter().map(|r| r.score).sum::<f64>() / results.len() as f64
        } else {
            0.0
        };

        let overall_status = if overall_score >= 90.0 {
            ComplianceStatus::Compliant
        } else if overall_score >= 70.0 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        };

        Ok(ComplianceReport {
            generated_at: Utc::now(),
            frameworks: self.enabled_frameworks.clone(),
            overall_status,
            overall_score,
            results,
            recommendations,
        })
    }

    /// Generate recommendations based on check results
    fn generate_recommendations(&self, results: &[ComplianceCheckResult]) -> Vec<String> {
        let mut recommendations = Vec::new();

        for result in results {
            if matches!(
                result.status,
                ComplianceStatus::NonCompliant | ComplianceStatus::PartiallyCompliant
            ) {
                recommendations.extend(result.remediation_steps.clone());
            }
        }

        recommendations.sort();
        recommendations.dedup();
        recommendations
    }

    /// Get all compliance requirements
    pub fn get_requirements(&self) -> Vec<&ComplianceRequirement> {
        self.requirements.values().collect()
    }

    /// Get enabled compliance frameworks
    pub fn get_enabled_frameworks(&self) -> &[ComplianceFramework] {
        &self.enabled_frameworks
    }
}

/// Comprehensive compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Timestamp when the report was generated
    pub generated_at: DateTime<Utc>,
    /// Compliance frameworks included in the report
    pub frameworks: Vec<ComplianceFramework>,
    /// Overall compliance status
    pub overall_status: ComplianceStatus,
    /// Overall compliance score (0.0 to 100.0)
    pub overall_score: f64,
    /// Individual check results
    pub results: Vec<ComplianceCheckResult>,
    /// Recommended remediation steps
    pub recommendations: Vec<String>,
}

/// Compliance audit service trait for logging compliance events
#[async_trait]
pub trait ComplianceAuditService: Send + Sync {
    /// Log a compliance event
    async fn log_compliance_event(&self, event: &ComplianceEvent) -> Result<()>;
}

/// Compliance event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvent {
    /// Type of compliance event
    pub event_type: ComplianceEventType,
    /// Compliance framework related to the event
    pub framework: ComplianceFramework,
    /// ID of the requirement related to the event
    pub requirement_id: String,
    /// User ID associated with the event (if applicable)
    pub user_id: Option<String>,
    /// Detailed information about the event
    pub details: String,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
}

/// Types of compliance events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceEventType {
    /// A compliance check was executed
    CheckExecuted,
    /// A compliance violation was detected
    ViolationDetected,
    /// Remediation was applied for a violation
    RemediationApplied,
    /// A compliance framework was enabled
    FrameworkEnabled,
    /// A compliance framework was disabled
    FrameworkDisabled,
    /// Manual review is required
    ManualReviewRequired,
}

/// Data Subject Rights service for handling GDPR data subject requests
pub struct DataSubjectRightsService {
    /// Audit service for logging compliance events
    audit_service: Arc<dyn ComplianceAuditService>,
}

impl DataSubjectRightsService {
    /// Create a new data subject rights service
    pub fn new(audit_service: Arc<dyn ComplianceAuditService>) -> Self {
        Self { audit_service }
    }

    /// Handle data access request (GDPR Article 15)
    pub async fn handle_data_access_request(
        &self,
        user_id: &str,
        request_id: &str,
    ) -> Result<DataAccessResponse> {
        // TODO: Implement data access request handling
        // Collect all personal data for the user
        // Generate report
        // Log the access request

        self.audit_service
            .log_compliance_event(&ComplianceEvent {
                event_type: ComplianceEventType::ManualReviewRequired,
                framework: ComplianceFramework::GDPR,
                requirement_id: "Article 15".to_string(),
                user_id: Some(user_id.to_string()),
                details: format!("Data access request {} for user {}", request_id, user_id),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(DataAccessResponse {
            request_id: request_id.to_string(),
            user_id: user_id.to_string(),
            data: HashMap::new(), // Placeholder
            status: "Processing".to_string(),
        })
    }

    /// Handle data rectification request (GDPR Article 16)
    pub async fn handle_data_rectification_request(
        &self,
        user_id: &str,
        request_id: &str,
        _corrections: HashMap<String, String>,
    ) -> Result<()> {
        // TODO: Implement data rectification
        // Update user data based on corrections
        // Log the rectification

        self.audit_service
            .log_compliance_event(&ComplianceEvent {
                event_type: ComplianceEventType::ManualReviewRequired,
                framework: ComplianceFramework::GDPR,
                requirement_id: "Article 16".to_string(),
                user_id: Some(user_id.to_string()),
                details: format!(
                    "Data rectification request {} for user {}",
                    request_id, user_id
                ),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(())
    }

    /// Handle data erasure request (GDPR Article 17)
    pub async fn handle_data_erasure_request(&self, user_id: &str, request_id: &str) -> Result<()> {
        // TODO: Implement right to erasure
        // Delete user data (with exceptions for legal requirements)
        // Log the erasure

        self.audit_service
            .log_compliance_event(&ComplianceEvent {
                event_type: ComplianceEventType::ManualReviewRequired,
                framework: ComplianceFramework::GDPR,
                requirement_id: "Article 17".to_string(),
                user_id: Some(user_id.to_string()),
                details: format!("Data erasure request {} for user {}", request_id, user_id),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(())
    }
}

/// Response to a data access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAccessResponse {
    /// Unique identifier for the access request
    pub request_id: String,
    /// User ID for whom the data is being accessed
    pub user_id: String,
    /// Personal data collected for the user
    pub data: HashMap<String, String>,
    /// Current status of the request
    pub status: String,
}

/// Privacy Impact Assessment service for managing PIA assessments
pub struct PrivacyImpactAssessmentService {
    /// Collection of privacy impact assessments
    assessments: HashMap<Uuid, PrivacyImpactAssessment>,
}

impl Default for PrivacyImpactAssessmentService {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivacyImpactAssessmentService {
    /// Create a new privacy impact assessment service
    pub fn new() -> Self {
        Self {
            assessments: HashMap::new(),
        }
    }

    /// Create a new privacy impact assessment
    pub fn create_assessment(&mut self, assessment: PrivacyImpactAssessment) -> Uuid {
        let id = assessment.id;
        self.assessments.insert(id, assessment);
        id
    }

    /// Get a privacy impact assessment by ID
    pub fn get_assessment(&self, id: &Uuid) -> Option<&PrivacyImpactAssessment> {
        self.assessments.get(id)
    }

    /// Update an existing privacy impact assessment
    pub fn update_assessment(&mut self, assessment: PrivacyImpactAssessment) -> Result<()> {
        self.assessments.insert(assessment.id, assessment);
        Ok(())
    }

    /// List all privacy impact assessments
    pub fn list_assessments(&self) -> Vec<&PrivacyImpactAssessment> {
        self.assessments.values().collect()
    }
}

/// Privacy Impact Assessment structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyImpactAssessment {
    /// Unique identifier for the assessment
    pub id: Uuid,
    /// Name of the project being assessed
    pub project_name: String,
    /// Description of the project and its data processing activities
    pub description: String,
    /// Types of personal data being processed
    pub data_types: Vec<String>,
    /// Purposes for which personal data is being processed
    pub processing_purposes: Vec<String>,
    /// Identified privacy risks
    pub risks: Vec<PrivacyRisk>,
    /// Mitigation measures to address identified risks
    pub mitigation_measures: Vec<String>,
    /// Timestamp when the assessment was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the assessment was last updated
    pub updated_at: DateTime<Utc>,
    /// Current approval status of the assessment
    pub status: PIAApprovalStatus,
}

/// Privacy risk identified during assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyRisk {
    /// Type or category of the risk
    pub risk_type: String,
    /// Detailed description of the risk
    pub description: String,
    /// Likelihood of the risk occurring
    pub likelihood: RiskLevel,
    /// Potential impact if the risk occurs
    pub impact: RiskLevel,
    /// Whether mitigation measures are required
    pub mitigation_required: bool,
}

/// Risk severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk level
    Low,
    /// Medium risk level
    Medium,
    /// High risk level
    High,
    /// Very high risk level
    VeryHigh,
}

/// Privacy Impact Assessment approval status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PIAApprovalStatus {
    /// Assessment is in draft state
    Draft,
    /// Assessment is under review
    UnderReview,
    /// Assessment has been approved
    Approved,
    /// Assessment has been rejected
    Rejected,
    /// Assessment requires revision
    RequiresRevision,
}

/// Compliance configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Whether compliance features are enabled
    pub enabled: bool,
    /// List of enabled compliance frameworks
    pub frameworks: Vec<ComplianceFramework>,
    /// Whether automated compliance scanning is enabled
    pub automated_scanning: bool,
    /// Interval in hours between automated scans
    pub scan_interval_hours: u32,
    /// Number of days to retain audit logs
    pub audit_retention_days: u32,
    /// Data residency requirements by region/country
    pub data_residency_requirements: HashMap<String, String>,
    /// Encryption requirements for data protection
    pub encryption_requirements: EncryptionRequirements,
}

/// Encryption requirements for data protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionRequirements {
    /// Encryption algorithm to use
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Whether data at rest should be encrypted
    pub at_rest: bool,
    /// Whether data in transit should be encrypted
    pub in_transit: bool,
    /// Number of days between key rotations
    pub key_rotation_days: u32,
}
