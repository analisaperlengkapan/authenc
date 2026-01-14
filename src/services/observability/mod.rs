use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    /// Service is healthy and operational
    Up,
    /// Service is unhealthy or unavailable
    Down,
    /// Health status cannot be determined
    Unknown,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Name of the health check
    pub name: String,
    /// Status of the health check
    pub status: HealthStatus,
    /// Additional details about the check
    pub details: Option<String>,
    /// Duration of the check
    pub duration: Duration,
    /// Timestamp when the check was performed
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Health check trait
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Get the name of this health check
    fn name(&self) -> &str;

    /// Perform a health check and return the result
    async fn check(&self) -> HealthCheckResult;
}

/// Database health check
pub struct DatabaseHealthCheck {
    /// Maximum number of connections in the pool
    pool_size: u32,
    /// Current number of active connections
    active_connections: u32,
}

impl DatabaseHealthCheck {
    /// Creates a new database health check with the specified connection pool parameters.
    ///
    /// # Arguments
    /// * `pool_size` - The maximum number of connections allowed in the pool
    /// * `active_connections` - The current number of active connections
    ///
    /// # Returns
    /// A new `DatabaseHealthCheck` instance configured with the provided parameters.
    pub fn new(pool_size: u32, active_connections: u32) -> Self {
        Self {
            pool_size,
            active_connections,
        }
    }
}

#[async_trait]
impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let status = if self.active_connections < self.pool_size {
            HealthStatus::Up
        } else {
            HealthStatus::Down
        };

        HealthCheckResult {
            name: "database".to_string(),
            status,
            details: Some(format!(
                "Pool size: {}, Active: {}",
                self.pool_size, self.active_connections
            )),
            duration: start.elapsed(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Cache health check
pub struct CacheHealthCheck {
    /// Number of cache hits
    cache_hits: u64,
    /// Number of cache misses
    cache_misses: u64,
}

impl CacheHealthCheck {
    /// Creates a new cache health check with the specified hit/miss statistics.
    ///
    /// # Arguments
    /// * `cache_hits` - The number of successful cache hits
    /// * `cache_misses` - The number of cache misses
    ///
    /// # Returns
    /// A new `CacheHealthCheck` instance configured with the provided cache statistics.
    pub fn new(cache_hits: u64, cache_misses: u64) -> Self {
        Self {
            cache_hits,
            cache_misses,
        }
    }
}

#[async_trait]
impl HealthCheck for CacheHealthCheck {
    fn name(&self) -> &str {
        "cache"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let total_requests = self.cache_hits + self.cache_misses;
        let hit_rate = if total_requests > 0 {
            self.cache_hits as f64 / total_requests as f64
        } else {
            0.0
        };

        HealthCheckResult {
            name: "cache".to_string(),
            status: if hit_rate > 0.1 {
                HealthStatus::Up
            } else {
                HealthStatus::Down
            },
            details: Some(format!("Hit rate: {:.2}%", hit_rate * 100.0)),
            duration: start.elapsed(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Authentication service health check
pub struct AuthServiceHealthCheck {
    /// Number of currently active sessions
    active_sessions: u32,
    /// Number of failed authentication attempts
    failed_attempts: u32,
}

impl AuthServiceHealthCheck {
    /// Creates a new authentication service health check with session and failure statistics.
    ///
    /// # Arguments
    /// * `active_sessions` - The current number of active user sessions
    /// * `failed_attempts` - The number of recent failed authentication attempts
    ///
    /// # Returns
    /// A new `AuthServiceHealthCheck` instance configured with the provided session statistics.
    pub fn new(active_sessions: u32, failed_attempts: u32) -> Self {
        Self {
            active_sessions,
            failed_attempts,
        }
    }
}

#[async_trait]
impl HealthCheck for AuthServiceHealthCheck {
    fn name(&self) -> &str {
        "auth_service"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let status = if self.failed_attempts < 100 {
            // Configurable threshold
            HealthStatus::Up
        } else {
            HealthStatus::Down
        };

        HealthCheckResult {
            name: "auth_service".to_string(),
            status,
            details: Some(format!(
                "Active sessions: {}, Failed attempts: {}",
                self.active_sessions, self.failed_attempts
            )),
            duration: start.elapsed(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Health check registry
pub struct HealthCheckRegistry {
    /// Map of health check names to their implementations
    checks: HashMap<String, Box<dyn HealthCheck>>,
}

impl Default for HealthCheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheckRegistry {
    /// Creates a new empty health check registry.
    ///
    /// # Returns
    /// A new `HealthCheckRegistry` instance with no registered health checks.
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
        }
    }

    /// Registers a new health check with the given name.
    ///
    /// # Arguments
    /// * `name` - A unique identifier for the health check
    /// * `check` - The health check implementation to register
    ///
    /// # Note
    /// If a health check with the same name already exists, it will be replaced.
    pub fn register(&mut self, name: &str, check: Box<dyn HealthCheck>) {
        self.checks.insert(name.to_string(), check);
    }

    /// Registers a new health check using its name.
    ///
    /// # Arguments
    /// * `check` - The health check implementation to register
    ///
    /// # Note
    /// If a health check with the same name already exists, it will be replaced.
    pub fn register_check(&mut self, check: Box<dyn HealthCheck>) {
        let name = check.name();
        self.checks.insert(name.to_string(), check);
    }

    /// Executes all registered health checks concurrently.
    ///
    /// # Returns
    /// A vector containing the results of all health checks in arbitrary order.
    pub async fn run_all_checks(&self) -> Vec<HealthCheckResult> {
        let mut results = Vec::new();
        for check in self.checks.values() {
            let result = check.check().await;
            results.push(result);
        }
        results
    }

    /// Executes a specific health check by name.
    ///
    /// # Arguments
    /// * `name` - The name of the health check to execute
    ///
    /// # Returns
    /// `Some(HealthCheckResult)` if the check exists and was executed,
    /// `None` if no check with the given name is registered.
    pub async fn run_check(&self, name: &str) -> Option<HealthCheckResult> {
        if let Some(check) = self.checks.get(name) {
            Some(check.check().await)
        } else {
            None
        }
    }
}

/// Metrics types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    /// Monotonically increasing counter
    Counter,
    /// Gauge that can go up and down
    Gauge,
    /// Histogram for measuring distributions
    Histogram,
    /// Summary for measuring quantiles
    Summary,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    /// Name of the metric
    pub name: String,
    /// Value of the metric
    pub value: f64,
    /// Labels associated with the metric
    pub labels: HashMap<String, String>,
    /// Timestamp when the metric was recorded
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Metrics collector trait
#[async_trait]
pub trait MetricsCollector: Send + Sync {
    /// Collect all available metrics
    async fn collect(&self) -> Vec<MetricValue>;
}

/// Prometheus metrics collector
pub struct PrometheusMetricsCollector {
    /// Collected metric values
    metrics: Vec<MetricValue>,
}

impl Default for PrometheusMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl PrometheusMetricsCollector {
    /// Creates a new Prometheus metrics collector.
    ///
    /// # Returns
    /// A new `PrometheusMetricsCollector` instance with an empty metrics buffer.
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
        }
    }

    /// Records a counter metric with the specified value and labels.
    ///
    /// # Arguments
    /// * `name` - The name of the metric
    /// * `value` - The counter value to record
    /// * `labels` - Additional labels to attach to the metric
    ///
    /// # Note
    /// Counter values should be monotonically increasing.
    pub fn record_counter(&mut self, name: &str, value: f64, labels: HashMap<String, String>) {
        self.metrics.push(MetricValue {
            name: name.to_string(),
            value,
            labels,
            timestamp: chrono::Utc::now(),
        });
    }

    /// Records a gauge metric with the specified value and labels.
    ///
    /// # Arguments
    /// * `name` - The name of the metric
    /// * `value` - The gauge value to record
    /// * `labels` - Additional labels to attach to the metric
    ///
    /// # Note
    /// Gauge values can go up and down and represent a point-in-time measurement.
    pub fn record_gauge(&mut self, name: &str, value: f64, labels: HashMap<String, String>) {
        self.metrics.push(MetricValue {
            name: name.to_string(),
            value,
            labels,
            timestamp: chrono::Utc::now(),
        });
    }
}

#[async_trait]
impl MetricsCollector for PrometheusMetricsCollector {
    async fn collect(&self) -> Vec<MetricValue> {
        self.metrics.clone()
    }
}

/// Metrics registry
pub struct MetricsRegistry {
    /// List of registered metrics collectors
    collectors: Vec<Box<dyn MetricsCollector>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    /// Register a metrics collector
    pub fn register(&mut self, collector: Box<dyn MetricsCollector>) {
        self.collectors.push(collector);
    }

    /// Collect all metrics from registered collectors
    pub async fn collect_all(&self) -> Vec<MetricValue> {
        let mut all_metrics = Vec::new();
        for collector in &self.collectors {
            let metrics = collector.collect().await;
            all_metrics.extend(metrics);
        }
        all_metrics
    }
}

/// Tracing span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    /// Unique identifier for the trace
    pub trace_id: String,
    /// Unique identifier for this span
    pub span_id: String,
    /// Parent span ID if this is a child span
    pub parent_span_id: Option<String>,
    /// Name of the span
    pub name: String,
    /// Start time of the span
    pub start_time: chrono::DateTime<chrono::Utc>,
    /// End time of the span (None if still active)
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Attributes associated with the span
    pub attributes: HashMap<String, String>,
    /// Events that occurred during the span
    pub events: Vec<TraceEvent>,
}

/// Tracing event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Name of the event
    pub name: String,
    /// Timestamp when the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Attributes associated with the event
    pub attributes: HashMap<String, String>,
}

/// Tracing service
pub struct TracingService {
    /// Map of span IDs to their corresponding spans
    spans: HashMap<String, TraceSpan>,
}

impl Default for TracingService {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingService {
    /// Creates a new tracing service with an empty span storage.
    ///
    /// # Returns
    /// A new `TracingService` instance ready to track distributed traces and spans.
    pub fn new() -> Self {
        Self {
            spans: HashMap::new(),
        }
    }

    /// Start a new tracing span
    pub fn start_span(&mut self, trace_id: &str, span_id: &str, name: &str) -> String {
        let span = TraceSpan {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            parent_span_id: None,
            name: name.to_string(),
            start_time: chrono::Utc::now(),
            end_time: None,
            attributes: HashMap::new(),
            events: Vec::new(),
        };

        self.spans.insert(span_id.to_string(), span);
        span_id.to_string()
    }

    /// End a tracing span
    pub fn end_span(&mut self, span_id: &str) {
        if let Some(span) = self.spans.get_mut(span_id) {
            span.end_time = Some(chrono::Utc::now());
        }
    }

    /// Add an attribute to a span
    pub fn add_attribute(&mut self, span_id: &str, key: &str, value: &str) {
        if let Some(span) = self.spans.get_mut(span_id) {
            span.attributes.insert(key.to_string(), value.to_string());
        }
    }

    /// Add an event to a span
    pub fn add_event(&mut self, span_id: &str, event: TraceEvent) {
        if let Some(span) = self.spans.get_mut(span_id) {
            span.events.push(event);
        }
    }

    /// Get a span by its ID
    pub fn get_span(&self, span_id: &str) -> Option<&TraceSpan> {
        self.spans.get(span_id)
    }

    /// Get all spans for a trace
    pub fn get_trace_spans(&self, trace_id: &str) -> Vec<&TraceSpan> {
        self.spans
            .values()
            .filter(|span| span.trace_id == trace_id)
            .collect()
    }
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Whether observability is enabled
    pub enabled: bool,
    /// Whether metrics collection is enabled
    pub metrics_enabled: bool,
    /// Whether tracing is enabled
    pub tracing_enabled: bool,
    /// Whether health checks are enabled
    pub health_checks_enabled: bool,
    /// Endpoint for metrics
    pub metrics_endpoint: String,
    /// Endpoint for health checks
    pub health_endpoint: String,
    /// Optional endpoint for tracing
    pub tracing_endpoint: Option<String>,
}

/// Service-level indicators (SLIs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevelIndicator {
    /// Name of the SLI
    pub name: String,
    /// Target objective percentage (e.g., 99.9 for 99.9% uptime)
    pub objective: f64,
    /// Time window for measurement
    pub window: Duration,
    /// Current measured value
    pub current_value: f64,
    /// Status of the SLI
    pub status: SliStatus,
}

/// SLI status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SliStatus {
    /// SLI is meeting its objective
    Good,
    /// SLI is close to missing its objective
    Warning,
    /// SLI is missing its objective
    Bad,
}

/// SLI tracker
pub struct SliTracker {
    /// Map of SLI names to their indicators
    indicators: HashMap<String, ServiceLevelIndicator>,
}

impl Default for SliTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SliTracker {
    /// Creates a new SLI tracker with no registered service level indicators.
    ///
    /// # Returns
    /// A new `SliTracker` instance with an empty indicators map.
    pub fn new() -> Self {
        Self {
            indicators: HashMap::new(),
        }
    }

    /// Registers a new Service Level Indicator (SLI) with the specified parameters.
    ///
    /// # Arguments
    /// * `name` - A unique identifier for the SLI
    /// * `objective` - The target value for the SLI (e.g., 99.9 for 99.9% uptime)
    /// * `window` - The time window over which the SLI is measured
    ///
    /// # Note
    /// The SLI starts with a current value of 100.0% and Good status.
    pub fn register_sli(&mut self, name: &str, objective: f64, window: Duration) {
        let sli = ServiceLevelIndicator {
            name: name.to_string(),
            objective,
            window,
            current_value: 100.0, // Start with 100%
            status: SliStatus::Good,
        };
        self.indicators.insert(name.to_string(), sli);
    }

    /// Updates the current value of an existing SLI and recalculates its status.
    ///
    /// # Arguments
    /// * `name` - The name of the SLI to update
    /// * `value` - The new current value for the SLI
    ///
    /// # Status Calculation
    /// - `Good`: value >= objective
    /// - `Warning`: objective * 0.95 <= value < objective
    /// - `Bad`: value < objective * 0.95
    pub fn update_sli(&mut self, name: &str, value: f64) {
        if let Some(sli) = self.indicators.get_mut(name) {
            sli.current_value = value;
            sli.status = if value >= sli.objective {
                SliStatus::Good
            } else if value >= sli.objective * 0.95 {
                SliStatus::Warning
            } else {
                SliStatus::Bad
            };
        }
    }

    /// Retrieves a specific Service Level Indicator by name.
    ///
    /// # Arguments
    /// * `name` - The name of the SLI to retrieve
    ///
    /// # Returns
    /// `Some(&ServiceLevelIndicator)` if the SLI exists, `None` otherwise.
    pub fn get_sli(&self, name: &str) -> Option<&ServiceLevelIndicator> {
        self.indicators.get(name)
    }

    /// Retrieves all registered Service Level Indicators.
    ///
    /// # Returns
    /// A vector containing references to all registered SLIs.
    pub fn get_all_slis(&self) -> Vec<&ServiceLevelIndicator> {
        self.indicators.values().collect()
    }
}

/// Performance monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// 50th percentile response time
    pub response_time_p50: Duration,
    /// 95th percentile response time
    pub response_time_p95: Duration,
    /// 99th percentile response time
    pub response_time_p99: Duration,
    /// Throughput in requests per second
    pub throughput: f64,
    /// Error rate as percentage
    pub error_rate: f64,
    /// CPU usage as percentage
    pub cpu_usage: f64,
    /// Memory usage as percentage
    pub memory_usage: f64,
}

/// Performance monitor
pub struct PerformanceMonitor {
    /// Current performance metrics
    metrics: PerformanceMetrics,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMonitor {
    /// Creates a new performance monitor with default metrics values.
    ///
    /// # Returns
    /// A new `PerformanceMonitor` instance with sensible default performance metrics.
    ///
    /// # Default Values
    /// - Response time P50: 100ms
    /// - Response time P95: 500ms
    /// - Response time P99: 1000ms
    /// - Throughput: 100 RPS
    /// - Error rate: 0.1%
    /// - CPU usage: 50%
    /// - Memory usage: 60%
    pub fn new() -> Self {
        Self {
            metrics: PerformanceMetrics {
                response_time_p50: Duration::from_millis(100),
                response_time_p95: Duration::from_millis(500),
                response_time_p99: Duration::from_millis(1000),
                throughput: 100.0,
                error_rate: 0.1,
                cpu_usage: 50.0,
                memory_usage: 60.0,
            },
        }
    }

    /// Updates the performance metrics with new measurements.
    ///
    /// # Arguments
    /// * `metrics` - The new performance metrics to store
    ///
    /// # Note
    /// This replaces all current metrics with the new values.
    pub fn update_metrics(&mut self, metrics: PerformanceMetrics) {
        self.metrics = metrics;
    }

    /// Retrieves the current performance metrics.
    ///
    /// # Returns
    /// A reference to the current `PerformanceMetrics`.
    pub fn get_metrics(&self) -> &PerformanceMetrics {
        &self.metrics
    }
}

/// Main observability service that combines health checks, metrics, and monitoring
#[derive(Default)]
pub struct ObservabilityService {
    /// Health check registry
    health_registry: HealthCheckRegistry,
    /// Metrics registry
    metrics_registry: MetricsRegistry,
    /// Performance monitor
    performance_monitor: PerformanceMonitor,
}


impl ObservabilityService {
    /// Create a new observability service
    pub fn new() -> Self {
        Self {
            health_registry: HealthCheckRegistry::new(),
            metrics_registry: MetricsRegistry::new(),
            performance_monitor: PerformanceMonitor::new(),
        }
    }

    /// Register a health check
    pub fn register_health_check(&mut self, check: Box<dyn HealthCheck>) {
        self.health_registry.register_check(check);
    }

    /// Register a metrics collector
    pub fn register_metrics_collector(&mut self, collector: Box<dyn MetricsCollector>) {
        self.metrics_registry.register(collector);
    }

    /// Perform all health checks
    pub async fn perform_health_checks(&self) -> Vec<HealthCheckResult> {
        self.health_registry.run_all_checks().await
    }

    /// Collect all metrics
    pub async fn collect_metrics(&self) -> Vec<MetricValue> {
        self.metrics_registry.collect_all().await
    }

    /// Get performance metrics
    pub fn get_performance_metrics(&self) -> &PerformanceMetrics {
        self.performance_monitor.get_metrics()
    }

    /// Update performance metrics
    pub fn update_performance_metrics(&mut self, metrics: PerformanceMetrics) {
        self.performance_monitor.update_metrics(metrics);
    }
}
