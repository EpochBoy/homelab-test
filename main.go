package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	// Build-time variables (set via ldflags)
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Logger - structured JSON logging for Loki
var logger *slog.Logger

// Tracer - OpenTelemetry tracer for Tempo
var tracer trace.Tracer

// RabbitMQ connection and channel
var (
	rabbitConn    *amqp.Connection
	rabbitChannel *amqp.Channel
	rabbitMu      sync.RWMutex
	rabbitEnabled bool
	// Stores last N consumed messages for demo display
	consumedMessages     []ConsumedMessage
	consumedMessagesMu   sync.RWMutex
	maxConsumedMessages  = 10
)

// ConsumedMessage holds a consumed message for display
type ConsumedMessage struct {
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
	TraceID   string    `json:"trace_id"`
}

// Prometheus metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epochcloud_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// Histogram with exemplars enabled for metric-to-trace drilldown
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:                        "epochcloud_http_request_duration_seconds",
			Help:                        "HTTP request duration in seconds",
			Buckets:                     prometheus.DefBuckets,
			NativeHistogramBucketFactor: 1.1, // Enable native histograms for better precision
		},
		[]string{"method", "path"},
	)

	appInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epochcloud_app_info",
			Help: "Application build information",
		},
		[]string{"version", "commit", "build_time", "environment"},
	)

	activeRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "epochcloud_active_requests",
			Help: "Number of currently active requests",
		},
	)

	errorRate = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epochcloud_errors_total",
			Help: "Total number of errors by type",
		},
		[]string{"type"},
	)

	// RabbitMQ metrics
	rabbitMessagesPublished = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "epochcloud_rabbitmq_messages_published_total",
			Help: "Total number of messages published to RabbitMQ",
		},
	)

	rabbitMessagesConsumed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "epochcloud_rabbitmq_messages_consumed_total",
			Help: "Total number of messages consumed from RabbitMQ",
		},
	)

	rabbitPublishErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "epochcloud_rabbitmq_publish_errors_total",
			Help: "Total number of publish errors",
		},
	)

	rabbitConnectionStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "epochcloud_rabbitmq_connected",
			Help: "RabbitMQ connection status (1=connected, 0=disconnected)",
		},
	)
)

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type VersionResponse struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	BuildTime   string `json:"buildTime"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"`
}

type PageData struct {
	Version     string
	Commit      string
	BuildTime   string
	Hostname    string
	Environment string
	Timestamp   string
}

const pageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EpochCloud Test | {{.Environment}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #e8e8e8;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .container { max-width: 800px; width: 100%; }
        .header { text-align: center; margin-bottom: 3rem; }
        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .env-badge {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 50px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 1rem;
        }
        .env-dev { background: #ff6b6b; color: #fff; }
        .env-staging { background: #feca57; color: #1a1a2e; }
        .env-prod { background: #00d26a; color: #fff; }
        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .card h2 {
            font-size: 1.25rem;
            color: #00d9ff;
            margin-bottom: 1rem;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .info-item {
            background: rgba(255, 255, 255, 0.03);
            padding: 1rem;
            border-radius: 8px;
        }
        .info-item label {
            font-size: 0.75rem;
            text-transform: uppercase;
            color: #888;
        }
        .info-item p {
            font-family: monospace;
            font-size: 0.9rem;
            color: #fff;
            word-break: break-all;
            margin-top: 0.25rem;
        }
        .pipeline {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        .pipeline-step {
            background: rgba(255, 255, 255, 0.1);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
        }
        .pipeline-arrow { color: #00d9ff; font-size: 1.5rem; }
        .observability {
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
        }
        .obs-item { text-align: center; padding: 1rem; }
        .obs-item .icon { font-size: 2rem; margin-bottom: 0.5rem; }
        .obs-item .label { font-size: 0.85rem; color: #00d9ff; }
        .obs-item .desc { font-size: 0.75rem; color: #888; }
        .footer { text-align: center; margin-top: 2rem; font-size: 0.85rem; color: #666; }
        .footer a { color: #00d9ff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 EpochCloud Test</h1>
            <p>GitOps proof-of-concept demonstrating the full CI/CD pipeline</p>
            <span class="env-badge env-{{.Environment}}">{{.Environment}}</span>
        </div>
        <div class="card">
            <h2>📦 Build Information</h2>
            <div class="info-grid">
                <div class="info-item"><label>Version</label><p>{{.Version}}</p></div>
                <div class="info-item"><label>Commit</label><p>{{.Commit}}</p></div>
                <div class="info-item"><label>Build Time</label><p>{{.BuildTime}}</p></div>
                <div class="info-item"><label>Hostname</label><p>{{.Hostname}}</p></div>
            </div>
        </div>
        <div class="card">
            <h2>📊 Observability Stack</h2>
            <p style="color: #888; margin-bottom: 1rem;">This app integrates with the full observability stack:</p>
            <div class="observability">
                <div class="obs-item"><div class="icon">📈</div><div class="label">Prometheus</div><div class="desc">Metrics at /metrics</div></div>
                <div class="obs-item"><div class="icon">📋</div><div class="label">Loki</div><div class="desc">JSON structured logs</div></div>
                <div class="obs-item"><div class="icon">🔍</div><div class="label">Tempo</div><div class="desc">Distributed tracing</div></div>
                <div class="obs-item"><div class="icon">��</div><div class="label">AlertManager</div><div class="desc">Error rate alerts</div></div>
            </div>
        </div>
        <div class="card">
            <h2>⚡ Deployment Pipeline</h2>
            <p style="color: #888; margin-bottom: 1rem;">Deployed through automated pipeline:</p>
            <div class="pipeline">
                <span class="pipeline-step">📝 Git Push</span>
                <span class="pipeline-arrow">→</span>
                <span class="pipeline-step">⚙️ Argo Workflows</span>
                <span class="pipeline-arrow">→</span>
                <span class="pipeline-step">🐳 Harbor</span>
                <span class="pipeline-arrow">→</span>
                <span class="pipeline-step">📦 Kargo</span>
                <span class="pipeline-arrow">→</span>
                <span class="pipeline-step">🚀 ArgoCD</span>
            </div>
        </div>
        <div class="card">
            <h2>� RabbitMQ Demo</h2>
            <p style="color: #888; margin-bottom: 1rem;">Message broker integration with pub/sub demo:</p>
            <div class="info-grid">
                <div class="info-item"><label>/rabbitmq/status</label><p>Connection status & consumed messages</p></div>
                <div class="info-item"><label>/rabbitmq/publish</label><p>Publish message (GET or POST)</p></div>
                <div class="info-item"><label>/rabbitmq/publish?message=Hello</label><p>Publish custom message</p></div>
            </div>
            <p style="color: #666; margin-top: 1rem; font-size: 0.8rem;">Messages auto-consumed by background worker. View metrics: epochcloud_rabbitmq_*</p>
        </div>
        <div class="card">
            <h2>�🔥 Chaos Testing</h2>
            <p style="color: #888; margin-bottom: 1rem;">Test the AlertManager → ntfy notification pipeline:</p>
            <div class="info-grid">
                <div class="info-item"><label>/chaos?action=error</label><p>Triggers 500 error, increments error counter</p></div>
                <div class="info-item"><label>/chaos?action=slow</label><p>Adds 2s latency for latency alerts</p></div>
                <div class="info-item"><label>/chaos?action=load&count=50</label><p>Simulates N concurrent requests</p></div>
            </div>
        </div>
        <div class="footer">
            <p>Last refreshed: {{.Timestamp}}</p>
        </div>
    </div>
</body>
</html>`

func getEnvironment() string {
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "dev"
	}
	return env
}

// initLogger sets up structured JSON logging for Loki
func initLogger() {
	hostname, _ := os.Hostname()
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger = slog.New(handler).With(
		slog.String("service", "epochcloud-test"),
		slog.String("version", Version),
		slog.String("environment", getEnvironment()),
		slog.String("hostname", hostname),
	)
	slog.SetDefault(logger)
}

// initTracer sets up OpenTelemetry tracing for Tempo
func initTracer(ctx context.Context) (*sdktrace.TracerProvider, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// Default to Alloy DaemonSet which receives OTLP and forwards to Tempo
		endpoint = "alloy.alloy.svc.cluster.local:4317"
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("epochcloud-test"),
			semconv.ServiceVersion(Version),
			attribute.String("environment", getEnvironment()),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = tp.Tracer("epochcloud-test")
	return tp, nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, span := tracer.Start(ctx, "healthCheck")
	defer span.End()

	resp := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	logger.InfoContext(ctx, "health check",
		slog.String("status", resp.Status),
		slog.String("trace_id", span.SpanContext().TraceID().String()),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, span := tracer.Start(ctx, "getVersion")
	defer span.End()

	hostname, _ := os.Hostname()
	resp := VersionResponse{
		Version:     Version,
		Commit:      Commit,
		BuildTime:   BuildTime,
		Hostname:    hostname,
		Environment: getEnvironment(),
	}

	logger.InfoContext(ctx, "version request",
		slog.String("version", Version),
		slog.String("trace_id", span.SpanContext().TraceID().String()),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, span := tracer.Start(ctx, "renderHomepage")
	defer span.End()

	hostname, _ := os.Hostname()
	data := PageData{
		Version:     Version,
		Commit:      Commit,
		BuildTime:   BuildTime,
		Hostname:    hostname,
		Environment: getEnvironment(),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		logger.ErrorContext(ctx, "template error",
			slog.String("error", err.Error()),
			slog.String("trace_id", span.SpanContext().TraceID().String()),
		)
		errorRate.WithLabelValues("template").Inc()
		span.RecordError(err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	logger.InfoContext(ctx, "homepage rendered",
		slog.String("environment", data.Environment),
		slog.String("trace_id", span.SpanContext().TraceID().String()),
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// ChaosResponse contains the result of a chaos test
type ChaosResponse struct {
	Action    string `json:"action"`
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// chaosHandler triggers errors/latency to test AlertManager → ntfy pipeline
// Usage:
//   GET /chaos?action=error       - Returns 500 and increments error counter
//   GET /chaos?action=slow        - Adds 2s latency to test latency alerts
//   GET /chaos?action=load&count=N - Simulates N concurrent requests
func chaosHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, span := tracer.Start(ctx, "chaosTest")
	defer span.End()

	action := r.URL.Query().Get("action")
	if action == "" {
		action = "error"
	}

	span.SetAttributes(attribute.String("chaos.action", action))

	var resp ChaosResponse
	resp.Action = action
	resp.Timestamp = time.Now().UTC().Format(time.RFC3339)

	switch action {
	case "error":
		// Trigger 500 error - increments epochcloud_errors_total
		errorRate.WithLabelValues("chaos_test").Inc()
		logger.ErrorContext(ctx, "chaos test triggered error",
			slog.String("action", action),
			slog.String("trace_id", span.SpanContext().TraceID().String()),
		)
		resp.Success = false
		resp.Message = "Simulated error for AlertManager testing. Check epochcloud_errors_total metric."
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)

	case "slow":
		// Add latency - tests latency alerts
		delay := 2 * time.Second
		logger.WarnContext(ctx, "chaos test adding latency",
			slog.String("action", action),
			slog.Duration("delay", delay),
			slog.String("trace_id", span.SpanContext().TraceID().String()),
		)
		time.Sleep(delay)
		resp.Success = true
		resp.Message = "Simulated slow response (2s delay). Check epochcloud_http_request_duration_seconds metric."
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case "load":
		// Simulate concurrent requests by incrementing activeRequests temporarily
		countStr := r.URL.Query().Get("count")
		count := 10
		if countStr != "" {
			if n, err := strconv.Atoi(countStr); err == nil && n > 0 && n <= 100 {
				count = n
			}
		}
		logger.InfoContext(ctx, "chaos test simulating load",
			slog.String("action", action),
			slog.Int("count", count),
			slog.String("trace_id", span.SpanContext().TraceID().String()),
		)
		// Increment and hold for 5 seconds to simulate load
		for i := 0; i < count; i++ {
			activeRequests.Inc()
		}
		time.Sleep(5 * time.Second)
		for i := 0; i < count; i++ {
			activeRequests.Dec()
		}
		resp.Success = true
		resp.Message = fmt.Sprintf("Simulated %d concurrent requests for 5s. Check epochcloud_active_requests metric.", count)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	default:
		resp.Success = false
		resp.Message = "Unknown action. Use: error, slow, or load"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
	}
}

// metricsMiddleware wraps handlers with metrics and tracing
// Records exemplars linking metrics to trace IDs for drilldown in Grafana
func metricsMiddleware(path string, next http.HandlerFunc) http.Handler {
	return otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		activeRequests.Inc()
		defer activeRequests.Dec()

		wrapped := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next(wrapped, r)

		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(r.Method, path, http.StatusText(wrapped.statusCode)).Inc()

		// Record histogram with exemplar containing trace_id for metric→trace drilldown
		// This allows clicking on a metric data point in Grafana to open the related trace
		span := trace.SpanFromContext(r.Context())
		traceID := span.SpanContext().TraceID().String()
		httpRequestDuration.WithLabelValues(r.Method, path).(prometheus.ExemplarObserver).ObserveWithExemplar(
			duration,
			prometheus.Labels{"trace_id": traceID},
		)

		logger.Info("request completed",
			slog.String("method", r.Method),
			slog.String("path", path),
			slog.Int("status", wrapped.statusCode),
			slog.Float64("duration_seconds", duration),
			slog.String("trace_id", traceID),
		)
	}), path)
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// initRabbitMQ starts background RabbitMQ connection manager with retry logic
func initRabbitMQ(ctx context.Context) error {
	host := os.Getenv("RABBITMQ_HOST")

	// If no host configured, RabbitMQ is optional
	if host == "" {
		logger.Info("RabbitMQ not configured, skipping initialization")
		rabbitConnectionStatus.Set(0)
		return nil
	}

	// Start background connection manager (non-blocking)
	go rabbitConnectionManager(ctx)

	return nil
}

// rabbitConnectionManager maintains RabbitMQ connection with exponential backoff retry
func rabbitConnectionManager(ctx context.Context) {
	host := os.Getenv("RABBITMQ_HOST")
	port := os.Getenv("RABBITMQ_PORT")
	user := os.Getenv("RABBITMQ_USERNAME")
	pass := os.Getenv("RABBITMQ_PASSWORD")
	vhost := os.Getenv("RABBITMQ_VHOST")

	if port == "" {
		port = "5672"
	}
	if vhost == "" {
		vhost = "/"
	}

	url := fmt.Sprintf("amqp://%s:%s@%s:%s/%s", user, pass, host, port, vhost)

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			logger.Info("RabbitMQ connection manager shutting down")
			return
		default:
		}

		// Check if already connected
		rabbitMu.RLock()
		connected := rabbitEnabled && rabbitConn != nil && !rabbitConn.IsClosed()
		rabbitMu.RUnlock()

		if connected {
			// Already connected, wait and check again
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		// Attempt connection
		logger.Info("attempting RabbitMQ connection",
			slog.String("host", host),
			slog.String("vhost", vhost),
		)

		conn, err := amqp.Dial(url)
		if err != nil {
			logger.Warn("RabbitMQ connection failed, will retry",
				slog.String("host", host),
				slog.String("error", err.Error()),
				slog.Duration("retry_in", backoff),
			)
			rabbitConnectionStatus.Set(0)

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		ch, err := conn.Channel()
		if err != nil {
			conn.Close()
			logger.Warn("RabbitMQ channel open failed, will retry",
				slog.String("error", err.Error()),
				slog.Duration("retry_in", backoff),
			)
			rabbitConnectionStatus.Set(0)

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Success - update state
		rabbitMu.Lock()
		rabbitConn = conn
		rabbitChannel = ch
		rabbitEnabled = true
		rabbitMu.Unlock()

		rabbitConnectionStatus.Set(1)
		backoff = time.Second // Reset backoff on success

		logger.Info("RabbitMQ connected",
			slog.String("host", host),
			slog.String("vhost", vhost),
		)

		// Start consumer for this connection
		consumerCtx, consumerCancel := context.WithCancel(ctx)
		go startConsumer(consumerCtx)

		// Wait for connection close notification
		closeChan := make(chan *amqp.Error, 1)
		conn.NotifyClose(closeChan)

		select {
		case <-ctx.Done():
			consumerCancel()
			return
		case amqpErr := <-closeChan:
			consumerCancel()
			if amqpErr != nil {
				logger.Warn("RabbitMQ connection lost, will reconnect",
					slog.String("error", amqpErr.Error()),
				)
			} else {
				logger.Info("RabbitMQ connection closed, will reconnect")
			}
			rabbitMu.Lock()
			rabbitEnabled = false
			rabbitConn = nil
			rabbitChannel = nil
			rabbitMu.Unlock()
			rabbitConnectionStatus.Set(0)
		}
	}
}

// startConsumer starts a background consumer for the demo queue
func startConsumer(ctx context.Context) {
	queueName := os.Getenv("RABBITMQ_QUEUE")
	if queueName == "" {
		queueName = "epochcloud-demo"
	}

	rabbitMu.RLock()
	ch := rabbitChannel
	enabled := rabbitEnabled
	rabbitMu.RUnlock()

	if !enabled || ch == nil {
		return
	}

	// Declare the queue (idempotent)
	_, err := ch.QueueDeclare(
		queueName,
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		logger.Error("failed to declare queue", slog.String("queue", queueName), slog.String("error", err.Error()))
		return
	}

	msgs, err := ch.Consume(
		queueName,
		"epochcloud-test-consumer", // consumer tag
		true,                       // auto-ack
		false,                      // exclusive
		false,                      // no-local
		false,                      // no-wait
		nil,                        // args
	)
	if err != nil {
		logger.Error("failed to start consumer", slog.String("queue", queueName), slog.String("error", err.Error()))
		return
	}

	logger.Info("RabbitMQ consumer started", slog.String("queue", queueName))

	for {
		select {
		case <-ctx.Done():
			logger.Info("RabbitMQ consumer shutting down")
			return
		case msg, ok := <-msgs:
			if !ok {
				logger.Warn("RabbitMQ consumer channel closed")
				rabbitConnectionStatus.Set(0)
				return
			}
			rabbitMessagesConsumed.Inc()

			consumed := ConsumedMessage{
				Body:      string(msg.Body),
				Timestamp: time.Now(),
				TraceID:   msg.MessageId, // Use MessageId as trace correlation
			}

			consumedMessagesMu.Lock()
			consumedMessages = append([]ConsumedMessage{consumed}, consumedMessages...)
			if len(consumedMessages) > maxConsumedMessages {
				consumedMessages = consumedMessages[:maxConsumedMessages]
			}
			consumedMessagesMu.Unlock()

			logger.Info("message consumed",
				slog.String("queue", queueName),
				slog.String("body", string(msg.Body)),
			)
		}
	}
}

// RabbitMQPublishRequest is the request body for publishing a message
type RabbitMQPublishRequest struct {
	Message string `json:"message"`
}

// RabbitMQResponse is the response for RabbitMQ operations
type RabbitMQResponse struct {
	Success   bool               `json:"success"`
	Message   string             `json:"message"`
	TraceID   string             `json:"trace_id,omitempty"`
	Consumed  []ConsumedMessage  `json:"consumed,omitempty"`
	Connected bool               `json:"connected"`
	Timestamp string             `json:"timestamp"`
}

// rabbitStatusHandler returns RabbitMQ connection status and consumed messages
func rabbitStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, span := tracer.Start(ctx, "rabbitStatus")
	defer span.End()

	rabbitMu.RLock()
	connected := rabbitEnabled && rabbitConn != nil && !rabbitConn.IsClosed()
	rabbitMu.RUnlock()

	consumedMessagesMu.RLock()
	messages := make([]ConsumedMessage, len(consumedMessages))
	copy(messages, consumedMessages)
	consumedMessagesMu.RUnlock()

	resp := RabbitMQResponse{
		Success:   true,
		Message:   "RabbitMQ status",
		Connected: connected,
		Consumed:  messages,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	logger.InfoContext(ctx, "rabbitmq status check",
		slog.Bool("connected", connected),
		slog.Int("consumed_messages", len(messages)),
		slog.String("trace_id", span.SpanContext().TraceID().String()),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// rabbitPublishHandler publishes a message to RabbitMQ
func rabbitPublishHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, span := tracer.Start(ctx, "rabbitPublish")
	defer span.End()

	rabbitMu.RLock()
	ch := rabbitChannel
	enabled := rabbitEnabled
	rabbitMu.RUnlock()

	if !enabled || ch == nil {
		resp := RabbitMQResponse{
			Success:   false,
			Message:   "RabbitMQ not connected",
			Connected: false,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Get message from query param or body
	message := r.URL.Query().Get("message")
	if message == "" && r.Method == http.MethodPost {
		var req RabbitMQPublishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			message = req.Message
		}
	}
	if message == "" {
		message = fmt.Sprintf("Hello from EpochCloud at %s", time.Now().Format(time.RFC3339))
	}

	queueName := os.Getenv("RABBITMQ_QUEUE")
	if queueName == "" {
		queueName = "epochcloud-demo"
	}

	traceID := span.SpanContext().TraceID().String()

	err := ch.PublishWithContext(ctx,
		"",        // exchange (default)
		queueName, // routing key (queue name)
		false,     // mandatory
		false,     // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(message),
			MessageId:   traceID, // Trace correlation
			Timestamp:   time.Now(),
		},
	)

	if err != nil {
		rabbitPublishErrors.Inc()
		logger.ErrorContext(ctx, "failed to publish message",
			slog.String("queue", queueName),
			slog.String("error", err.Error()),
			slog.String("trace_id", traceID),
		)
		resp := RabbitMQResponse{
			Success:   false,
			Message:   "Failed to publish: " + err.Error(),
			Connected: true,
			TraceID:   traceID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	rabbitMessagesPublished.Inc()
	logger.InfoContext(ctx, "message published",
		slog.String("queue", queueName),
		slog.String("message", message),
		slog.String("trace_id", traceID),
	)

	resp := RabbitMQResponse{
		Success:   true,
		Message:   fmt.Sprintf("Published to %s: %s", queueName, message),
		Connected: true,
		TraceID:   traceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// closeRabbitMQ closes RabbitMQ connections
func closeRabbitMQ() {
	rabbitMu.Lock()
	defer rabbitMu.Unlock()

	if rabbitChannel != nil {
		rabbitChannel.Close()
		rabbitChannel = nil
	}
	if rabbitConn != nil {
		rabbitConn.Close()
		rabbitConn = nil
	}
	rabbitEnabled = false
	rabbitConnectionStatus.Set(0)
	logger.Info("RabbitMQ connections closed")
}

func main() {
	initLogger()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tp, err := initTracer(ctx)
	if err != nil {
		logger.Warn("failed to initialize tracer", slog.String("error", err.Error()))
		tracer = otel.Tracer("epochcloud-test")
	} else {
		defer func() {
			shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			tp.Shutdown(shutdownCtx)
		}()
	}

	// Start RabbitMQ connection manager (non-blocking, handles retries internally)
	initRabbitMQ(ctx)
	defer closeRabbitMQ()

	appInfo.WithLabelValues(Version, Commit, BuildTime, getEnvironment()).Set(1)

	mux := http.NewServeMux()
	mux.Handle("/", metricsMiddleware("/", rootHandler))
	mux.Handle("/health", metricsMiddleware("/health", healthHandler))
	mux.Handle("/version", metricsMiddleware("/version", versionHandler))
	mux.Handle("/chaos", metricsMiddleware("/chaos", chaosHandler))
	// RabbitMQ demo endpoints
	mux.Handle("/rabbitmq/status", metricsMiddleware("/rabbitmq/status", rabbitStatusHandler))
	mux.Handle("/rabbitmq/publish", metricsMiddleware("/rabbitmq/publish", rabbitPublishHandler))
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		logger.Info("shutting down")
		cancel() // Cancel context to stop RabbitMQ consumer
		shutdownCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		server.Shutdown(shutdownCtx)
	}()

	logger.Info("starting server", slog.String("port", port), slog.String("version", Version))
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
