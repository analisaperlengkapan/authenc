# Kafka Audit Log Streaming Integration

## Overview

The Authenc platform now supports advanced enterprise audit logging with Kafka-based distributed streaming capabilities. This feature provides both streaming and persistent audit logging with graceful fallback mechanisms.

## Architecture

### Multi-Sink Audit Logging
- **Primary Sink**: Kafka for distributed streaming
- **Fallback Sink**: PostgreSQL for persistent storage
- **Automatic Fallback**: System continues operating if Kafka is unavailable

### Key Components

#### 1. Configuration (`src/config.rs`)
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub audit_topic: String,
    pub producer_config: Option<HashMap<String, String>>,
}
```

#### 2. Audit Log Sink Trait (`src/services/audit_log_sink.rs`)
```rust
#[async_trait]
pub trait AuditLogSink: Send + Sync {
    async fn log_event(&self, event: AuditEvent) -> Result<(), AuthencError>;
    async fn log_events(&self, events: Vec<AuditEvent>) -> Result<(), AuthencError>;
}
```

#### 3. Kafka Implementation (`src/services/kafka_audit_log_sink.rs`)
- Uses `rdkafka` crate for Kafka producer
- Configurable brokers and topic
- Error handling with retry logic

#### 4. PostgreSQL Implementation (`src/services/pg_audit_log_sink.rs`)
- Fallback storage using existing PostgreSQL infrastructure
- Maintains audit trail integrity

## Configuration

### Environment Variables
```bash
# Kafka Configuration
KAFKA_BROKERS=localhost:9092,localhost:9093
KAFKA_AUDIT_TOPIC=authenc-audit-events
KAFKA_PRODUCER_ACKS=all
KAFKA_PRODUCER_RETRIES=3
```

### AppState Integration
The audit log sink is initialized conditionally in `AppState::new()`:
- If Kafka configuration is provided and connection succeeds → Use KafkaAuditLogSink
- If Kafka fails or is not configured → Use PgAuditLogSink

## Testing

### Test Coverage
- **Audit Logging Tests**: 4 tests covering basic audit functionality
- **Kafka Integration Tests**: 6 tests covering Kafka-specific features
- **Integration Tests**: 9 tests ensuring system-wide functionality
- **End-to-End Tests**: 8 tests validating complete workflows

### Running Tests
```bash
# Run all audit-related tests
cargo test audit_log --lib --quiet

# Run Kafka integration tests
cargo test --test kafka_integration_tests -- --nocapture

# Run full integration suite
cargo test --test integration_tests --quiet
```

## Features

### Enterprise-Grade Reliability
- **Graceful Degradation**: System operates with PostgreSQL if Kafka is unavailable
- **Message Durability**: Configurable producer acks and retries
- **Error Handling**: Comprehensive error handling with logging

### Observability
- **Distributed Streaming**: Real-time audit event streaming to Kafka
- **Persistent Storage**: All events stored in PostgreSQL for compliance
- **Monitoring**: Integration with existing metrics and monitoring systems

### Security
- **Audit Trail Integrity**: No audit events are lost during failures
- **Compliance Ready**: Supports enterprise audit requirements
- **Zero Trust**: Events include comprehensive context for security analysis

## Usage

### Automatic Integration
The Kafka audit logging is automatically integrated into the existing audit system. No code changes are required for existing audit logging calls.

### Configuration Example
```rust
// In your configuration
let kafka_config = KafkaConfig {
    brokers: vec!["localhost:9092".to_string()],
    audit_topic: "authenc-audit-events".to_string(),
    producer_config: Some(HashMap::from([
        ("acks".to_string(), "all".to_string()),
        ("retries".to_string(), "3".to_string()),
    ])),
};
```

## Benefits

1. **Scalability**: Handle high-volume audit logging with Kafka's distributed architecture
2. **Reliability**: Dual-sink approach ensures no audit events are lost
3. **Observability**: Real-time streaming enables advanced monitoring and alerting
4. **Compliance**: Enterprise-grade audit trails for regulatory requirements
5. **Performance**: Asynchronous logging doesn't impact application performance

## Future Enhancements

- **Schema Registry Integration**: Structured audit event schemas
- **Consumer Applications**: Real-time dashboards and alerting
- **Advanced Filtering**: Topic partitioning and consumer group management
- **Metrics Integration**: Detailed audit logging metrics and monitoring</content>
<parameter name="filePath">/home/clouduser/authence/authenc/docs/KAFKA_AUDIT_INTEGRATION.md
