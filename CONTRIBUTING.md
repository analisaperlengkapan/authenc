# Contributing to Authenc

Thank you for your interest in contributing to Authenc! We welcome contributions from developers of all skill levels.

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/authenc.git
   cd authenc
   ```
3. **Create a new branch** for your feature/bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🛠 Development Setup

### Prerequisites
- Rust 1.75+ (latest stable)
- PostgreSQL 12+ (for integration tests)
- Git

### Local Development
```bash
# Install dependencies
cargo build

# Run tests
cargo test

# Run with development config
cargo run

# Check code quality
cargo clippy
cargo fmt --check
```

## 📝 Contribution Guidelines

### Code Standards
- **Follow Rust idioms**: Use `cargo clippy` and `cargo fmt`
- **Write tests**: All new functionality must include tests
- **Document your code**: Add doc comments for public APIs
- **Security first**: Security-related changes require extra scrutiny
- **Modular design**: Maintain separation of concerns

### Testing Requirements
- **Unit tests** for individual functions and modules
- **Integration tests** for API endpoints and middleware
- **Security tests** for authentication and authorization features
- All tests must pass: `cargo test`
- No decrease in test coverage

### Commit Guidelines
- **Clear commit messages**: Use descriptive, concise commit messages
- **Atomic commits**: One logical change per commit
- **Conventional commits** preferred:
  ```
  feat: add TOTP authentication support
  fix: resolve rate limiter memory leak
  docs: update API documentation
  test: add security middleware tests
  ```

### Pull Request Process

1. **Update documentation** if needed
2. **Add/update tests** for your changes
3. **Ensure CI passes**: All tests and checks must pass
4. **Write clear PR description**:
   - What changes were made?
   - Why were they necessary?
   - How were they tested?
5. **Link related issues** if applicable
6. **Request review** from maintainers

## 🎯 Types of Contributions

### 🐛 Bug Reports
- Use GitHub Issues with the "bug" label
- Include steps to reproduce
- Provide system information (OS, Rust version)
- Include error messages and logs

### ✨ Feature Requests
- Use GitHub Issues with the "enhancement" label
- Describe the use case and expected behavior
- Consider backward compatibility

### 📚 Documentation
- API documentation improvements
- Code examples and tutorials
- README updates
- Architecture documentation

### 🔒 Security
- Security issues should be reported privately to: security@cipherce.com
- Follow responsible disclosure practices
- Security fixes are high priority

## 🏗 Architecture Guidelines

### Code Organization
```
src/
├── app.rs              # Application builder and configuration
├── config.rs           # Configuration management
├── error.rs            # Error types and handling
├── handlers/           # HTTP request handlers
├── middleware/         # Security and utility middleware
├── models/             # Data models and schemas
├── services/           # Business logic and data access
└── utils/              # Shared utility functions
```

### Key Principles
- **Security by default**: All endpoints should be secure by default
- **Configuration driven**: Use environment variables for configuration
- **Testable**: Write code that's easy to test
- **Error handling**: Comprehensive error handling with proper logging
- **Performance**: Consider performance implications of changes

## 🔍 Code Review Process

1. **Automated checks**: CI/CD pipeline runs tests and lints
2. **Maintainer review**: At least one maintainer must approve
3. **Community feedback**: Other contributors may provide input
4. **Iterative improvement**: Address feedback in new commits
5. **Merge**: Maintainers merge approved PRs

## 📋 Checklist for Contributors

Before submitting a PR, ensure:

- [ ] Code follows Rust best practices (`cargo clippy` passes)
- [ ] Code is properly formatted (`cargo fmt`)
- [ ] All tests pass (`cargo test`)
- [ ] New functionality includes tests
- [ ] Documentation is updated if needed
- [ ] CHANGELOG.md is updated for significant changes
- [ ] No sensitive information is committed
- [ ] Branch is up to date with main

## 🏷 Issue Labels

- `bug` - Something isn't working
- `enhancement` - New feature or improvement
- `documentation` - Documentation improvements
- `security` - Security-related issues
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed

## 💬 Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community discussion
- **Email**: security@cipherce.com for security issues

## 📄 License

By contributing to Authenc, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Authenc! Your efforts help make authentication and authorization more secure and accessible for everyone.
