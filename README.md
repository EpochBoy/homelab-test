# homelab-test

Test repository for homelab Kubernetes cluster CI/CD pipeline testing.

## Purpose

- **Woodpecker CI**: Validates baseline security pipeline injection
- **Kargo**: Tests environment promotion (dev → staging → prod)
- **Argo Rollouts**: Validates canary/blue-green deployments
- **DAST**: Post-deployment security scanning with OWASP ZAP

## Application

Simple Go web server that returns JSON health status and version info.

## Local Development

```bash
# Run locally
go run main.go

# Build container
docker build -t homelab-test .

# Test locally
curl http://localhost:8080/health
curl http://localhost:8080/version
```

## Deployment

This app is deployed via:
1. **Woodpecker CI** builds and pushes to Harbor
2. **ArgoCD Image Updater** detects new images
3. **Kargo** promotes through stages (when configured)
4. **Argo Rollouts** handles progressive delivery

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (for probes) |
| `GET /version` | Version info (git commit, build time) |
| `GET /` | Welcome page |
