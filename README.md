# homelab-test

Test repository for homelab Kubernetes cluster CI/CD pipeline testing.

## Quick Links

| 🌐 Live Sites | 📦 Repos |
|:--------------|:---------|
| [🧪 Test (Prod)](https://test.epoch.engineering) | [🏠 Homelab Infra](https://github.com/EpochBoy/homelab) |
| [🔬 Staging](https://test-staging.epoch.engineering) | |
| [🧑‍💻 Dev](https://test-dev.epoch.engineering) | |

## Purpose

This is a **proof-of-concept app** demonstrating the complete homelab deployment flow.

App repos should be **minimal** - just source code and a Dockerfile. Everything else (deployment manifests, CI pipelines, monitoring) lives in the **infra repo**.

## What's in this repo (app concerns)

```text
homelab-test/
├── Dockerfile              # How to build the app
├── main.go, go.mod         # Source code
├── VERSION                 # App version
└── README.md               # This file
```

## What's in the infra repo (platform concerns)

```text
homelab/
├── kubernetes/apps/homelab-test/    # Deployment manifests
├── ansible/tasks/homelab-test-*.yml # ArgoCD + Kargo Applications
└── kubernetes/infrastructure/       # CI pipelines (Argo Workflows)
```

## Complete Deployment Flow

```text
1. DEVELOPER PUSHES CODE
   └── Push to EpochBoy/homelab-test main branch

2. ARGO WORKFLOWS CI (webhook triggered)
   └── GitHub App EventSource triggers app-baseline pipeline:
       ├── Pre-build: Semgrep SAST, TruffleHog secrets, OSV-Scanner SCA
       ├── Build: Buildah container build + push to Harbor
       └── Post-build: Trivy scan, Grype CVE, Syft SBOM, Cosign signing

3. IMAGE PUSHED TO HARBOR
   └── registry.epoch.engineering/homelab/homelab-test:<sha>

4. KARGO DETECTS NEW IMAGE (Warehouse polls Harbor)
   └── Auto-promotes to dev environment

5. KARGO PROMOTES TO STAGING
   └── Auto-promotion policy triggers staging deployment
   └── OWASP ZAP DAST scan runs as verification gate

6. KARGO PROMOTES TO PRODUCTION
   └── Manual promotion required (click in Kargo UI)
   └── ArgoCD syncs production deployment
```

## Deployment Tools

| Tool | What it does | When it runs |
|------|--------------|--------------|
| **Renovate** | Updates Dockerfile base images (alpine, golang) | Creates PRs for external deps |
| **Kargo** | Promotes images through dev→staging→prod | After Argo Workflows pushes to Harbor |
| **ArgoCD** | Syncs deployments to cluster | When Kargo updates image tags |

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

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (for probes) |
| `GET /version` | Version info (git commit, build time) |
| `GET /` | Welcome page |
# CI Test Fri Dec 26 18:07:17 CET 2025
