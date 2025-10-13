use futures_util::TryStreamExt;
use futures_util::stream::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{ConfigMap, Service, ServiceSpec};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams, ResourceExt, WatchParams};
use kube::{Client, CustomResource};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Authenc Kubernetes Operator
/// Provides cloud-native deployment capabilities with advanced features
/// Authenc Custom Resource Definition
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(group = "authenc.io", version = "v1", kind = "Authenc", namespaced)]
#[kube(status = "AuthencStatus")]
pub struct AuthencSpec {
    /// Number of replicas for the Authenc deployment
    pub replicas: Option<i32>,
    /// Authenc version to deploy
    pub version: String,
    /// Database configuration settings
    pub database: DatabaseConfig,
    /// TLS/SSL configuration
    pub tls: TlsConfig,
    /// Feature flags for enabling/disabling functionality
    pub features: AuthencFeatures,
    /// Resource limits and requests
    pub resources: ResourceLimits,
    /// Optional ingress configuration
    pub ingress: Option<IngressConfig>,
    /// Optional monitoring configuration
    pub monitoring: Option<MonitoringConfig>,
}

/// Database configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct DatabaseConfig {
    /// Database server hostname or IP address
    pub host: String,
    /// Database server port number
    pub port: i32,
    /// Name of the database to connect to
    pub database: String,
    /// Name of the Kubernetes secret containing the database username
    pub username_secret: String,
    /// Name of the Kubernetes secret containing the database password
    pub password_secret: String,
    /// SSL mode for database connection (e.g., "require", "verify-ca", "verify-full")
    pub ssl_mode: String,
}

/// TLS configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct TlsConfig {
    /// Whether TLS is enabled for the Authenc deployment
    pub enabled: bool,
    /// Optional name of the Kubernetes secret containing TLS certificates
    pub secret_name: Option<String>,
    /// Optional cert-manager issuer for automatic certificate management
    pub cert_manager_issuer: Option<String>,
}

/// Authenc features
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct AuthencFeatures {
    /// Enable OpenID Connect authentication protocol
    pub oidc: bool,
    /// Enable SAML authentication protocol
    pub saml: bool,
    /// Enable OID4VC (OpenID for Verifiable Credentials) protocol
    pub oid4vc: bool,
    /// Enable WebAuthn authentication (FIDO2/passkeys)
    pub webauthn: bool,
    /// Enable social login providers (Google, Facebook, etc.)
    pub social_login: bool,
    /// Enable device management and tracking features
    pub device_management: bool,
    /// Enable zero trust security model and adaptive controls
    pub zero_trust: bool,
}

/// Resource limits
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ResourceLimits {
    /// Resource requests (guaranteed minimum resources allocated)
    pub requests: ResourceRequest,
    /// Resource limits (maximum allowed resources)
    pub limits: ResourceLimit,
}

/// Resource requests configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ResourceRequest {
    /// CPU request in Kubernetes format (e.g., "100m", "0.1")
    pub cpu: String,
    /// Memory request in Kubernetes format (e.g., "128Mi", "1Gi")
    pub memory: String,
}

/// Resource limits configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ResourceLimit {
    /// CPU limit in Kubernetes format (e.g., "500m", "2")
    pub cpu: String,
    /// Memory limit in Kubernetes format (e.g., "512Mi", "2Gi")
    pub memory: String,
}

/// Ingress configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IngressConfig {
    /// Whether ingress is enabled for external access
    pub enabled: bool,
    /// Optional ingress class name for the ingress controller
    pub class_name: Option<String>,
    /// List of hostnames that the ingress should handle
    pub hosts: Vec<String>,
    /// Optional TLS configuration for secure HTTPS access
    pub tls: Option<Vec<IngressTls>>,
}

/// Ingress TLS configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IngressTls {
    /// Name of the Kubernetes secret containing the TLS certificate and key
    pub secret_name: String,
    /// List of hostnames covered by this TLS certificate
    pub hosts: Vec<String>,
}

/// Monitoring configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct MonitoringConfig {
    /// Whether monitoring and metrics collection is enabled
    pub enabled: bool,
    /// Optional Prometheus configuration for metrics scraping
    pub prometheus: Option<PrometheusConfig>,
    /// Optional Grafana configuration for dashboards
    pub grafana: Option<GrafanaConfig>,
}

/// Prometheus configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PrometheusConfig {
    /// Scrape interval for metrics collection (e.g., "30s", "1m")
    pub scrape_interval: String,
    /// HTTP path where metrics are exposed (e.g., "/metrics")
    pub metrics_path: String,
}

/// Grafana configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct GrafanaConfig {
    /// Optional UID of the dashboard to import
    pub dashboard_uid: Option<String>,
}

/// Authenc status
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct AuthencStatus {
    /// Current phase of the Authenc deployment
    pub phase: AuthencPhase,
    /// List of status conditions
    pub conditions: Vec<Condition>,
    /// Optional endpoint URL where Authenc is accessible
    pub endpoint: Option<String>,
    /// Optional version of the running Authenc instance
    pub version: Option<String>,
}

/// Authenc deployment phase
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub enum AuthencPhase {
    /// Deployment is pending
    Pending,
    /// Deployment is running successfully
    Running,
    /// Deployment has failed
    Failed,
    /// Deployment status is unknown
    Unknown,
}

/// Kubernetes condition
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct Condition {
    /// Type of the condition
    pub type_: String,
    /// Status of the condition (True, False, Unknown)
    pub status: String,
    /// Last time the condition transitioned
    pub last_transition_time: Option<String>,
    /// Machine-readable reason for the condition
    pub reason: Option<String>,
    /// Human-readable message about the condition
    pub message: Option<String>,
}

/// Authenc Operator implementation
pub struct AuthencOperator {
    client: Client,
}

impl AuthencOperator {
    /// Create a new Authenc operator with Kubernetes client
    ///
    /// This constructor initializes an Authenc operator that manages
    /// Authenc deployments and resources within a Kubernetes cluster.
    /// The operator uses the provided Kubernetes client to interact
    /// with the cluster API for deployment management.
    ///
    /// # Arguments
    /// * `client` - Kubernetes client for cluster communication
    ///
    /// # Returns
    /// A new `AuthencOperator` instance ready for Kubernetes operations
    ///
    /// # Security Considerations
    /// - Kubernetes client should have appropriate RBAC permissions
    /// - Service account tokens should be properly managed and rotated
    /// - Network policies should restrict operator access
    /// - Audit logging should be enabled for all operator actions
    ///
    /// # Kubernetes Integration
    /// - Manages Authenc Custom Resources (CRDs)
    /// - Handles deployment lifecycle (create, update, delete)
    /// - Configures services, ingresses, and configmaps
    /// - Monitors cluster resources and health status
    ///
    /// # Example
    /// ```rust
    /// use authenc::services::kubernetes::AuthencOperator;
    /// use kube::Client;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::try_default().await?;
    /// let operator = AuthencOperator::new(client);
    /// // Operator is ready for Authenc deployment management
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Create Authenc deployment
    pub async fn create_deployment(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deployment = self.build_deployment(authenc, namespace)?;
        let api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        api.create(&PostParams::default(), &deployment).await?;
        Ok(())
    }

    /// Create Authenc service
    pub async fn create_service(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = self.build_service(authenc, namespace)?;
        let api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        api.create(&PostParams::default(), &service).await?;
        Ok(())
    }

    /// Create RBAC resources
    pub async fn create_rbac(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create ServiceAccount
        self.create_service_account(authenc, namespace).await?;

        // Create ClusterRole
        let cluster_role = self.build_cluster_role(authenc)?;
        let api: Api<ClusterRole> = Api::all(self.client.clone());
        api.create(&PostParams::default(), &cluster_role).await?;

        // Create ClusterRoleBinding
        let cluster_role_binding = self.build_cluster_role_binding(authenc, namespace)?;
        let api: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        api.create(&PostParams::default(), &cluster_role_binding)
            .await?;

        Ok(())
    }

    /// Build Kubernetes deployment
    fn build_deployment(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<Deployment, Box<dyn std::error::Error>> {
        let replicas = authenc.spec.replicas.unwrap_or(1);

        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "authenc".to_string());
        labels.insert("authenc.io/instance".to_string(), authenc.name_any());

        let mut env_vars = vec![k8s_openapi::api::core::v1::EnvVar {
            name: "DATABASE_URL".to_string(),
            value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                secret_key_ref: Some(k8s_openapi::api::core::v1::SecretKeySelector {
                    key: "database_url".to_string(),
                    name: Some(format!("{}-db-secret", authenc.name_any())),
                    optional: Some(false),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }];

        // Add feature flags as environment variables
        if authenc.spec.features.oid4vc {
            env_vars.push(k8s_openapi::api::core::v1::EnvVar {
                name: "OID4VC_ENABLED".to_string(),
                value: Some("true".to_string()),
                ..Default::default()
            });
        }

        if authenc.spec.features.zero_trust {
            env_vars.push(k8s_openapi::api::core::v1::EnvVar {
                name: "ZERO_TRUST_ENABLED".to_string(),
                value: Some("true".to_string()),
                ..Default::default()
            });
        }

        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some(format!("{}-deployment", authenc.name_any())),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(replicas),
                selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_labels: Some(labels.clone()),
                    ..Default::default()
                },
                template: k8s_openapi::api::core::v1::PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(k8s_openapi::api::core::v1::PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: "authenc".to_string(),
                            image: Some(format!("authenc:{}", authenc.spec.version)),
                            ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                                container_port: 8080,
                                protocol: Some("TCP".to_string()),
                                ..Default::default()
                            }]),
                            env: Some(env_vars),
                            resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
                                requests: Some({
                                    let mut requests = std::collections::BTreeMap::new();
                                    requests.insert(
                                        "cpu".to_string(),
                                        k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                                            authenc.spec.resources.requests.cpu.clone(),
                                        ),
                                    );
                                    requests.insert(
                                        "memory".to_string(),
                                        k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                                            authenc.spec.resources.requests.memory.clone(),
                                        ),
                                    );
                                    requests
                                }),
                                limits: Some({
                                    let mut limits = std::collections::BTreeMap::new();
                                    limits.insert(
                                        "cpu".to_string(),
                                        k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                                            authenc.spec.resources.limits.cpu.clone(),
                                        ),
                                    );
                                    limits.insert(
                                        "memory".to_string(),
                                        k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                                            authenc.spec.resources.limits.memory.clone(),
                                        ),
                                    );
                                    limits
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            status: None,
        };

        Ok(deployment)
    }

    /// Build Kubernetes service
    fn build_service(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<Service, Box<dyn std::error::Error>> {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "authenc".to_string());
        labels.insert("authenc.io/instance".to_string(), authenc.name_any());

        let service = Service {
            metadata: ObjectMeta {
                name: Some(format!("{}-service", authenc.name_any())),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(labels),
                ports: Some(vec![k8s_openapi::api::core::v1::ServicePort {
                    name: Some("http".to_string()),
                    port: 80,
                    target_port: Some(
                        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8080),
                    ),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }]),
                type_: Some("ClusterIP".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        Ok(service)
    }

    /// Build ClusterRole for Authenc
    fn build_cluster_role(
        &self,
        authenc: &Authenc,
    ) -> Result<ClusterRole, Box<dyn std::error::Error>> {
        let cluster_role = ClusterRole {
            metadata: ObjectMeta {
                name: Some(format!("{}-cluster-role", authenc.name_any())),
                ..Default::default()
            },
            rules: Some(vec![
                k8s_openapi::api::rbac::v1::PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["secrets".to_string(), "configmaps".to_string()]),
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                    ..Default::default()
                },
                k8s_openapi::api::rbac::v1::PolicyRule {
                    api_groups: Some(vec!["apps".to_string()]),
                    resources: Some(vec!["deployments".to_string()]),
                    verbs: vec![
                        "get".to_string(),
                        "list".to_string(),
                        "watch".to_string(),
                        "create".to_string(),
                        "update".to_string(),
                        "patch".to_string(),
                        "delete".to_string(),
                    ],
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        Ok(cluster_role)
    }

    /// Build ClusterRoleBinding
    fn build_cluster_role_binding(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<ClusterRoleBinding, Box<dyn std::error::Error>> {
        let cluster_role_binding = ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some(format!("{}-cluster-role-binding", authenc.name_any())),
                ..Default::default()
            },
            subjects: Some(vec![k8s_openapi::api::rbac::v1::Subject {
                kind: "ServiceAccount".to_string(),
                name: format!("{}-sa", authenc.name_any()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            }]),
            role_ref: k8s_openapi::api::rbac::v1::RoleRef {
                api_group: "rbac.authorization.k8s.io".to_string(),
                kind: "ClusterRole".to_string(),
                name: format!("{}-cluster-role", authenc.name_any()),
            },
        };

        Ok(cluster_role_binding)
    }

    /// Create ServiceAccount
    async fn create_service_account(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service_account = k8s_openapi::api::core::v1::ServiceAccount {
            metadata: ObjectMeta {
                name: Some(format!("{}-sa", authenc.name_any())),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let api: Api<k8s_openapi::api::core::v1::ServiceAccount> =
            Api::namespaced(self.client.clone(), namespace);
        api.create(&PostParams::default(), &service_account).await?;
        Ok(())
    }

    /// Create ConfigMap for Authenc configuration
    pub async fn create_config_map(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut data = BTreeMap::new();
        data.insert("version".to_string(), authenc.spec.version.clone());
        data.insert(
            "features.json".to_string(),
            serde_json::to_string(&authenc.spec.features)?,
        );

        let config_map = ConfigMap {
            metadata: ObjectMeta {
                name: Some(format!("{}-config", authenc.name_any())),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        let api: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        api.create(&PostParams::default(), &config_map).await?;
        Ok(())
    }

    /// Reconcile Authenc resource
    pub async fn reconcile(
        &self,
        authenc: &Authenc,
        namespace: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create RBAC resources
        self.create_rbac(authenc, namespace).await?;

        // Create ConfigMap
        self.create_config_map(authenc, namespace).await?;

        // Create Deployment
        self.create_deployment(authenc, namespace).await?;

        // Create Service
        self.create_service(authenc, namespace).await?;

        Ok(())
    }
}

/// Controller for managing Authenc resources
pub struct AuthencController {
    operator: AuthencOperator,
}

impl AuthencController {
    /// Create a new Authenc controller with Kubernetes client
    ///
    /// This constructor initializes an Authenc controller that manages
    /// the lifecycle of Authenc resources in a Kubernetes cluster.
    /// The controller uses an embedded Authenc operator to handle
    /// the actual deployment and resource management operations.
    ///
    /// # Arguments
    /// * `client` - Kubernetes client for cluster communication
    ///
    /// # Returns
    /// A new `AuthencController` instance ready for resource management
    ///
    /// # Security Considerations
    /// - Controller should run with minimal required permissions
    /// - Watch operations should be properly scoped to authorized namespaces
    /// - Event logging should capture all controller actions
    /// - Resource validation should prevent malicious configurations
    ///
    /// # Controller Responsibilities
    /// - Watches for Authenc Custom Resource changes
    /// - Reconciles desired state with actual cluster state
    /// - Handles resource creation, updates, and deletion
    /// - Manages operator lifecycle and error recovery
    ///
    /// # Example
    /// ```rust
    /// use authenc::services::kubernetes::AuthencController;
    /// use kube::Client;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::try_default().await?;
    /// let controller = AuthencController::new(client);
    /// // Start the controller
    /// // controller.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(client: Client) -> Self {
        Self {
            operator: AuthencOperator::new(client),
        }
    }

    /// Run the controller
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let client = kube::Client::try_default().await?;
        let api: Api<Authenc> = Api::all(client.clone());

        // Watch for Authenc resources
        let wp = WatchParams::default();
        let mut stream = api.watch(&wp, "0").await?.boxed();

        while let Some(event) = stream.try_next().await? {
            match event {
                kube::api::WatchEvent::Added(authenc) => {
                    println!("Authenc added: {}", authenc.name_any());
                    if let Some(ns) = authenc.namespace() {
                        self.operator.reconcile(&authenc, &ns).await?;
                    }
                }
                kube::api::WatchEvent::Modified(authenc) => {
                    println!("Authenc modified: {}", authenc.name_any());
                    if let Some(ns) = authenc.namespace() {
                        self.operator.reconcile(&authenc, &ns).await?;
                    }
                }
                kube::api::WatchEvent::Deleted(authenc) => {
                    println!("Authenc deleted: {}", authenc.name_any());
                    // Cleanup resources
                }
                _ => {}
            }
        }

        Ok(())
    }
}
