# Authenc by Cipherce - Optimized Project Structure

## 📁 Project Structure Overview

```
authenc/
├── src/                          # Main source code (clean architecture)
│   ├── main.rs                   # Application entry point
│   ├── app.rs                    # Application builder and configuration
│   ├── config.rs                 # Environment-based configuration
│   ├── error.rs                  # Comprehensive error handling
│   │
│   ├── database/                 # Database layer
│   │   ├── mod.rs               # Database connection pool
│   │   ├── queries.rs           # SQL queries organized by domain
│   │   └── migrations/          # Database migration files
│   │
│   ├── handlers/                 # HTTP request handlers (API layer)
│   │   ├── mod.rs               # Route configuration
│   │   ├── health.rs            # Health check endpoints
│   │   ├── audit.rs             # Audit log endpoints
│   │   ├── group.rs             # Group management
│   │   ├── session.rs           # Session management
│   │   ├── totp.rs              # TOTP authentication
│   │   ├── oidc_*.rs            # OpenID Connect providers
│   │   └── api/                 # Legacy API handlers (to be refactored)
│   │
│   ├── middleware/               # HTTP middleware
│   │   ├── mod.rs               # Middleware exports
│   │   ├── security.rs          # Security headers & sanitization
│   │   ├── rate_limit.rs        # Rate limiting
│   │   ├── auth_middleware.rs   # Authentication middleware
│   │   └── rbac.rs              # Role-based access control
│   │
│   ├── services/                 # Business logic layer
│   │   ├── mod.rs               # Service exports
│   │   ├── *_store.rs           # Data storage services
│   │   ├── anomaly_detector.rs  # Security anomaly detection
│   │   ├── brute_force_protector.rs # Brute force protection
│   │   ├── federation_provider.rs   # Identity federation
│   │   ├── password_policy.rs   # Password validation
│   │   └── audit_log_sink.rs    # Audit logging system
│   │
│   ├── models/                   # Domain models
│   │   ├── mod.rs               # Model exports
│   │   ├── user.rs              # User domain model
│   │   ├── realm.rs             # Realm/tenant model
│   │   ├── role.rs              # Role model
│   │   ├── permission.rs        # Permission model
│   │   ├── audit_log.rs         # Audit log model
│   │   └── oidc_client.rs       # OIDC client model
│   │
│   └── utils/                    # Utility modules
│       ├── mod.rs               # Utility exports
│       ├── jwt.rs               # JWT token handling
│       ├── i18n.rs              # Internationalization
│       ├── plugin.rs            # Plugin system
│       ├── auth_context.rs      # Authentication context
│       ├── crypto/              # Cryptographic utilities
│       ├── core/                # Core utilities
│       └── integration/         # Integration utilities
│
├── lib.rs                        # Library root (re-exports)
├── config/                       # Configuration files
│   └── openapi.yaml             # OpenAPI specification
├── docs/                         # Documentation
├── tests/                        # Integration tests
└── target/                       # Build artifacts
```

## 🚀 Key Improvements

### 1. **Clean Architecture**
- **Separation of Concerns**: Clear boundaries between layers
- **Dependency Inversion**: Services depend on abstractions, not implementations
- **Single Responsibility**: Each module has a single, well-defined purpose

### 2. **Optimized Structure**
- **src/**: All source code centralized in standard Rust location
- **Layered Approach**: handlers → services → models → database
- **Utility Consolidation**: All utilities organized under `utils/`

### 3. **Enhanced Error Handling**
- **Comprehensive Error Types**: AuthencError enum with HTTP status mapping
- **Error Propagation**: Proper error chains with context
- **User-Friendly Messages**: I18n support for error messages

### 4. **Configuration Management**
- **Environment-Based**: All configuration via environment variables
- **Validation**: Configuration validation at startup
- **Defaults**: Sensible defaults for development

### 5. **Security First**
- **Middleware Stack**: Security headers, rate limiting, CSRF protection
- **Authentication**: JWT-based with proper validation
- **Authorization**: RBAC with fine-grained permissions
- **Audit Logging**: Comprehensive audit trail

### 6. **Database Optimization**
- **Connection Pooling**: Efficient database connection management  
- **Query Organization**: SQL queries organized by domain
- **Migration System**: Structured database schema management

### 7. **Observability**
- **Structured Logging**: JSON-formatted logs with proper levels
- **Health Checks**: Health, readiness, and liveness endpoints
- **Metrics**: Prometheus metrics integration
- **Tracing**: Distributed tracing support

## 🛠 Development Workflow

### Building
```bash
cargo build --release
```

### Running
```bash
cargo run
```

### Testing
```bash
cargo test
```

### Environment Setup
Create `.env` file:
```bash
DATABASE_URL=postgres://user:pass@localhost/authenc
JWT_SECRET=your-super-secret-key
LOG_LEVEL=info
AUTHENCE_HOST=0.0.0.0
AUTHENCE_PORT=8080
```

## 📊 Performance & Scalability

- **Async/Await**: Full async implementation with Tokio
- **Connection Pooling**: Database connection reuse
- **Rate Limiting**: Prevent abuse and ensure stability
- **Caching**: Strategic caching for frequently accessed data
- **Horizontal Scaling**: Stateless design for load balancing

## 🔒 Security Features

- **Zero Trust Architecture**: Verify everything, trust nothing
- **Multi-Factor Authentication**: TOTP support
- **Session Management**: Secure session handling
- **Brute Force Protection**: Intelligent attack detection
- **Anomaly Detection**: Behavioral analysis
- **Audit Logging**: Complete audit trail

## 📝 Next Steps

1. **API Documentation**: Complete OpenAPI specification
2. **Integration Tests**: Comprehensive test coverage
3. **Performance Testing**: Load and stress testing
4. **Deployment**: Container and cloud deployment guides
5. **Monitoring**: Production monitoring setup

This optimized structure provides a solid foundation for a scalable, secure, and maintainable identity and access management system.
