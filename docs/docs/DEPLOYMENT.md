# Authenc by Cipherce Deployment Guide

This guide provides best practices for deploying Authenc securely and reliably in production environments.

## 1. Build the Release Binary
```
cargo build --release
```

## 2. Environment Variables
- Use environment variables for secrets (JWT keys, DB credentials, etc.)
- Example: `export AUTHENC_JWT_SECRET=your-secret-key` (backward compat: AUTHENCE_JWT_SECRET still read if set)

## 3. Reverse Proxy (Recommended)
- Deploy behind NGINX, Caddy, or Traefik for TLS termination and DDoS protection.
- Example NGINX config:
```
server {
    listen 443 ssl;
    server_name your-domain.com;
    ssl_certificate /etc/ssl/certs/your.crt;
    ssl_certificate_key /etc/ssl/private/your.key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 4. Systemd Service Example
Create `/etc/systemd/system/authenc.service`:
```
[Unit]
Description=Authenc IAM Server (by Cipherce)
After=network.target

[Service]
Type=simple
User=authenc
WorkingDirectory=/opt/authenc
ExecStart=/opt/authenc/target/release/authenc
Restart=on-failure
Environment=AUTHENC_JWT_SECRET=your-secret-key

[Install]
WantedBy=multi-user.target
```

## 5. Logging & Monitoring
- Use Prometheus to scrape `/metrics` endpoint.
- Forward logs to a central system (e.g., Loki, ELK).

## 6. Database
- Use a production-grade database (e.g., PostgreSQL).
- Secure DB access with strong passwords and network rules.

## 7. Security Best Practices
- Always use HTTPS in production.
- Rotate secrets regularly.
- Enable rate limiting (already built-in).
- Keep dependencies up to date.

## 8. Backup & Disaster Recovery
- Regularly backup database and configuration.
- Test restore procedures.

## 9. Scaling
- Use a process manager or orchestrator (systemd, Docker, Kubernetes).
- Run multiple instances behind a load balancer for high availability.

## 10. Zero Trust & Compliance
- Integrate with your organization's zero trust and compliance policies.
- Enable audit logging and review regularly.

---
For more details, see the official documentation and security.md.
