2025-08-15 - [Brute Force Protection and Account Lockout]
Vulnerability: The login endpoint lacked IP-based rate limiting and account lockout mechanisms, making it susceptible to brute-force and dictionary attacks.
Learning: Even with strong password policies, authentication endpoints require defense-in-depth measures like temporal lockouts and IP-based throttling to mitigate automated attacks. Axum's `ConnectInfo` extractor combined with a shared state `BruteForceProtector` provides an effective way to track and block malicious IPs before reaching expensive cryptographic operations.
Prevention: Always implement rate limiting on sensitive endpoints (login, password reset) and enforce account lockout state in the user model to protect against credential stuffing.
