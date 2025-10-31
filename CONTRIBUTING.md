# Contributing to Authenc

Thank you for your interest in contributing to Authenc! We welcome contributions from developers of all skill levels and backgrounds.

## Development Setup

### Prerequisites

- Rust 1.90 or later
- PostgreSQL 13+
- Git

### Getting Started

1. Fork the repository on GitHub
2. Clone your fork:
```bash
git clone https://github.com/your-username/authenc.git
cd authenc
```

3. Set up the development environment:
```bash
# Copy environment template
cp .env.example .env

# Set up database
createdb authenc_dev

# Install dependencies
cargo build
```

4. Run tests to ensure everything works:
```bash
cargo test
```

## Development Workflow

### 1. Choose an Issue

- Check [GitHub Issues](https://github.com/analisaperlengkapan/authenc/issues) for open tasks
- Look for issues labeled `good first issue` or `help wanted`
- Comment on the issue to indicate you're working on it

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 3. Make Changes

- Follow Rust best practices and idioms
- Add tests for new functionality
- Update documentation as needed
- Ensure code compiles and tests pass

### 4. Commit Changes

```bash
# Stage your changes
git add .

# Commit with a clear message
git commit -m "feat: add new authentication method

- Implement OAuth2 device flow
- Add device code generation
- Update API documentation
- Add comprehensive tests"
```

### 5. Push and Create Pull Request

```bash
# Push your branch
git push origin feature/your-feature-name

# Create a pull request on GitHub
```

## Code Standards

### Rust Guidelines

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo clippy` to check for common mistakes
- Format code with `cargo fmt`
- Write comprehensive documentation for public APIs
- Prefer `Result` over panics for error handling

### Commit Messages

Follow [Conventional Commits](https://conventionalcommits.org/) format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

### Testing

- Write unit tests for all public functions
- Add integration tests for API endpoints
- Include edge cases and error conditions
- Aim for high test coverage (>80%)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_creation() {
        // Test implementation
    }
}
```

## Architecture Guidelines

### Service Provider Interface (SPI)

Authenc uses SPI for extensibility. When adding new providers:

1. Implement the appropriate SPI trait
2. Register the provider in the SPI manager
3. Add configuration options
4. Write tests
5. Update documentation

### Database Operations

- Use the existing store pattern for data access
- Implement proper error handling
- Add database migrations for schema changes
- Ensure thread safety with Arc/RwLock where needed

### Security Considerations

- Never log sensitive information
- Use secure random number generation
- Implement proper input validation
- Follow OWASP guidelines
- Consider timing attacks in cryptographic operations

## Areas for Contribution

### High Priority

- **Social Login Providers**: Implement OAuth2/OIDC integrations (Google, GitHub, Microsoft)
- **LDAP/Active Directory**: Enterprise directory federation
- **Web Admin UI**: React/Vue.js administration interface
- **Documentation**: API docs, tutorials, deployment guides

### Medium Priority

- **Performance Optimization**: Database query optimization, caching
- **Monitoring**: Metrics collection, alerting, dashboards
- **Testing**: Additional test coverage, integration tests
- **Security**: Vulnerability assessments, security hardening

### Good First Issues

- Documentation improvements
- Test coverage enhancements
- Code refactoring and cleanup
- Minor bug fixes
- UI/UX improvements

## Pull Request Process

1. **Ensure CI Passes**: All tests must pass, code must compile
2. **Code Review**: At least one maintainer must review
3. **Documentation**: Update relevant docs for API changes
4. **Changelog**: Add entry to CHANGELOG.md for user-facing changes

### PR Template

Please use this template for pull requests:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code compiles without warnings
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Changelog updated (if applicable)
```

## Community

- **Discussions**: Use [GitHub Discussions](https://github.com/analisaperlengkapan/authenc/discussions) for questions
- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/analisaperlengkapan/authenc/issues)
- **Code of Conduct**: Please follow our [Code of Conduct](CODE_OF_CONDUCT.md)

## Recognition

Contributors will be recognized in:
- CHANGELOG.md for significant contributions
- GitHub's contributor insights
- Release notes
- Project documentation

Thank you for contributing to Authenc! 🎉