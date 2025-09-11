use futures_util::stream::StreamExt;
use futures_util::TryStreamExt;
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
    /// Number of replicas
    pub replicas: Option<i32>,

    /// Authenc version
    pub version: String,

    /// Database configuration
    pub database: DatabaseConfig,

    /// TLS configuration
    pub tls: TlsConfig,

    /// Feature flags
    pub features: AuthencFeatures,

    /// Resource limits
    pub resources: ResourceLimits,

    /// Ingress configuration
    pub ingress: Option<IngressConfig>,

    /// Monitoring configuration
    pub monitoring: Option<MonitoringConfig>,
}

/// Database configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: i32,
    pub database: String,
    pub username_secret: String,
    pub password_secret: String,
    pub ssl_mode: String,
}

/// TLS configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct TlsConfig {
    pub enabled: bool,
    pub secret_name: Option<String>,
    pub cert_manager_issuer: Option<String>,
}

/// Authenc features
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct AuthencFeatures {
    pub oidc: bool,
    pub saml: bool,
    pub oid4vc: bool,
    pub webauthn: bool,
    pub social_login: bool,
    pub device_management: bool,
    pub zero_trust: bool,
}

/// Resource limits
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ResourceLimits {
    pub requests: ResourceRequest,
    pub limits: ResourceLimit,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ResourceRequest {
    pub cpu: String,
    pub memory: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ResourceLimit {
    pub cpu: String,
    pub memory: String,
}

/// Ingress configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IngressConfig {
    pub enabled: bool,
    pub class_name: Option<String>,
    pub hosts: Vec<String>,
    pub tls: Option<Vec<IngressTls>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IngressTls {
    pub secret_name: String,
    pub hosts: Vec<String>,
}

/// Monitoring configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub prometheus: Option<PrometheusConfig>,
    pub grafana: Option<GrafanaConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PrometheusConfig {
    pub scrape_interval: String,
    pub metrics_path: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct GrafanaConfig {
    pub dashboard_uid: Option<String>,
}

/// Authenc status
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct AuthencStatus {
    pub phase: AuthencPhase,
    pub conditions: Vec<Condition>,
    pub endpoint: Option<String>,
    pub version: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub enum AuthencPhase {
    Pending,
    Running,
    Failed,
    Unknown,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct Condition {
    pub type_: String,
    pub status: String,
    pub last_transition_time: Option<String>,
    pub reason: Option<String>,
    pub message: Option<String>,
}

/// Authenc Operator implementation
pub struct AuthencOperator {
    client: Client,
}

impl AuthencOperator {
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
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
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
            ..Default::default()
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
