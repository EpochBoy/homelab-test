# epochcloud-test

Test repository for EpochCloud Kubernetes cluster CI/CD pipeline testing.

## Quick Links

| 🌐 Live Sites | 📦 Repos |
| :------------- | :-------- |
| [🧪 Test (Prod)](https://test.<your-domain>) | [☁️ EpochCloud Infra](https://github.com/EpochBoy/epochcloud) |
| [🔬 Staging](https://test-staging.<your-domain>) | |
| [🧑‍💻 Dev](https://test-dev.<your-domain>) | |

## Purpose

This is a **proof-of-concept app** demonstrating the complete EpochCloud deployment flow and observability stack integration.

App repos should be **minimal** - just source code and a Dockerfile. Everything else (deployment manifests, CI pipelines, monitoring) lives in the **infra repo**.

## What's in this repo (app concerns)

```text
epochcloud-test/
├── Dockerfile              # How to build the app
├── main.go, go.mod         # Source code with OTEL + slog
├── VERSION                 # App version
└── README.md               # This file
```

## What's in the infra repo (platform concerns)

```text
epochcloud/
├── kubernetes/apps/epochcloud-test/    # Deployment manifests + PrometheusRule
└── kubernetes/infrastructure/       # CI pipelines (Argo Workflows)
```

## Complete Deployment Flow

```text
1. DEVELOPER PUSHES CODE
   └── Push to EpochBoy/epochcloud-test main branch

2. ARGO WORKFLOWS CI (webhook triggered)
   └── GitHub App EventSource triggers app-baseline pipeline:
       ├── Pre-build: Semgrep SAST, TruffleHog secrets, OSV-Scanner SCA
       ├── Build: Buildah container build + push to Harbor
       └── Post-build: Trivy scan, Grype CVE, Syft SBOM, Cosign signing

3. IMAGE PUSHED TO HARBOR
   └── registry.<your-domain>/epochcloud/epochcloud-test:<sha>

4. KARGO PROMOTES THROUGH ENVIRONMENTS
   Each promotion triggers an Argo Rollout with canary analysis:

   DEV (auto-promote)
   └── Rollout: 10% → analysis → 25% → 50% → analysis → 75% → 100%
   └── Prometheus checks error rate, latency, success rate
   └── Auto-rollback if analysis fails
       ↓
   STAGING (auto-promote)
   └── Same canary rollout with Prometheus analysis
   └── OWASP ZAP DAST scan as Kargo verification gate
       ↓
   PRODUCTION (manual promote via Kargo UI)
   └── Same canary rollout with Prometheus analysis
   └── Traffic split via Traefik weighted TraefikService
```

## Local Development

```bash
# Run locally
go run main.go

# Build container
docker build -t epochcloud-test .

# Test endpoints
curl http://localhost:8080/health
curl http://localhost:8080/version
curl http://localhost:8080/metrics
```

## Endpoints

| Endpoint | Description |
| -------- | ----------- |
| `GET /` | Homepage with observability info |
| `GET /health` | Health check (for Kubernetes probes) |
| `GET /version` | Version info (commit, build time, environment) |
| `GET /metrics` | Prometheus metrics (scraped automatically) |
| `GET /chaos?action=X` | Chaos testing for AlertManager → ntfy |

## Observability Stack Integration

This app demonstrates **full observability integration** with the EpochCloud platform:

### 📈 Prometheus Metrics

The `/metrics` endpoint exposes:

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `epochcloud_http_requests_total` | Counter | Total HTTP requests by method, path, status |
| `epochcloud_http_request_duration_seconds` | Histogram | Request latency (p50, p95, p99) |
| `epochcloud_app_info` | Gauge | App metadata (version, commit, environment) |
| `epochcloud_active_requests` | Gauge | Currently active requests |
| `epochcloud_errors_total` | Counter | Errors by type |

### 📋 Loki Structured Logging

Using Go's `slog` package for JSON structured logs:

```json
{
  "time": "2025-01-05T12:00:00Z",
  "level": "INFO",
  "msg": "request completed",
  "service": "epochcloud-test",
  "version": "1.2.3",
  "environment": "prod",
  "hostname": "epochcloud-test-abc123",
  "method": "GET",
  "path": "/health",
  "status": 200,
  "duration_seconds": 0.001,
  "trace_id": "abc123def456"
}
```

Logs are collected by **Grafana Alloy** (DaemonSet) and shipped to **Loki**.

### 🔍 Tempo Distributed Tracing

OpenTelemetry instrumentation sends traces to **Tempo** via OTLP gRPC:

- All HTTP handlers create spans
- Trace IDs are logged for correlation (Loki → Tempo)
- Uses `otelhttp` middleware for automatic HTTP tracing

### 🔔 AlertManager → ntfy Alerts

PrometheusRule defines alerts that fire to ntfy via webhook:

| Alert | Condition | Severity |
| ----- | --------- | -------- |
| `EpochCloudTestHighErrorRate` | >5% errors over 5m | warning |
| `EpochCloudTestHighLatency` | P99 > 500ms | warning |
| `EpochCloudTestDown` | No instances running | critical |
| `EpochCloudTestHighLoad` | >50 concurrent requests | info |

## 🔥 Chaos Testing

Test the full alert pipeline with chaos endpoints:

```bash
# Trigger 500 errors - tests error rate alert
curl https://test.<your-domain>/chaos?action=error

# Add 2s latency - tests latency alert  
curl https://test.<your-domain>/chaos?action=slow

# Simulate 50 concurrent requests - tests load alert
curl https://test.<your-domain>/chaos?action=load&count=50
```

**Alert Flow:**
```
/chaos?action=error → epochcloud_errors_total ↑ → Prometheus scrapes →
AlertManager fires EpochCloudTestHighErrorRate → ntfy webhook →
ntfy.epochcloud-warning topic → mobile notification
```

## Platform Integration

| Component | How it integrates |
| --------- | ----------------- |
| **PodMonitor** | Auto-discovers pods with `app: epochcloud-test` label |
| **Grafana Alloy** | Collects JSON logs → Loki |
| **OpenTelemetry Collector** | Receives OTLP traces → Tempo |
| **PrometheusRule** | Defines alerts → AlertManager → ntfy |
| **Kargo + Argo Rollouts** | Promotes images with canary analysis |
| **ArgoCD** | GitOps deployment from infra repo |

## Environment Variables

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `PORT` | HTTP server port | `8080` |
| `ENVIRONMENT` | Environment name (dev/staging/prod) | `dev` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint | `opentelemetry-collector-agent.monitoring:4317` |
