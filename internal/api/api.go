// Package api exposes the fingerprinting engine over HTTP.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/version"
)

// Config carries the server's operational limits.
type Config struct {
	MaxBatch     int
	MaxBodyBytes int64
	Version      string
}

// Server wires the engine and the HTTP transport together.
type Server struct {
	engine   *fingerprint.Engine
	logger   *slog.Logger
	maxBatch int
	maxBody  int64
	version  string
	started  time.Time
}

// New constructs an API server. Defaults keep the zero-config path safe.
func New(engine *fingerprint.Engine, logger *slog.Logger, cfg Config) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 10000
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 16 << 20 // 16 MiB
	}
	if cfg.Version == "" {
		cfg.Version = version.Version
	}
	return &Server{
		engine:   engine,
		logger:   logger,
		maxBatch: cfg.MaxBatch,
		maxBody:  cfg.MaxBodyBytes,
		version:  cfg.Version,
		started:  time.Now(),
	}
}

// Handler returns the fully instrumented HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /fingerprint", s.handleFingerprint)

	// Outer to inner: request id / headers -> access log -> panic recovery.
	return s.withRequestID(s.withAccessLog(s.withRecovery(mux)))
}

type healthResponse struct {
	Status        string `json:"status"`
	Service       string `json:"service"`
	Version       string `json:"version"`
	Rules         int    `json:"rules"`
	RuleFiles     int    `json:"rule_files"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	info := s.engine.Info()
	status := "ok"
	code := http.StatusOK
	if info.Rules == 0 {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, healthResponse{
		Status:        status,
		Service:       "banner-fingerprint",
		Version:       s.version,
		Rules:         info.Rules,
		RuleFiles:     len(info.Files),
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body exceeds %d bytes", s.maxBody))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}

	records, err := decodeRecords(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if len(records) == 0 {
		writeJSON(w, http.StatusOK, []model.Fingerprint{})
		return
	}
	if len(records) > s.maxBatch {
		writeError(w, http.StatusBadRequest, "batch_too_large",
			fmt.Sprintf("batch contains %d records; limit is %d", len(records), s.maxBatch))
		return
	}

	results := s.engine.IdentifyBatch(records)
	writeJSON(w, http.StatusOK, results)

	if rid, _ := r.Context().Value(requestIDKey{}).(string); rid != "" {
		unknown := 0
		for _, fp := range results {
			if fp.Protocol == model.UnknownProtocol {
				unknown++
			}
		}
		s.logger.Info("fingerprint batch processed",
			"request_id", rid, "records", len(records), "unknown", unknown)
	}
}

// decodeRecords accepts both the compact contract (a JSON array) and the
// convenience envelope {"items": [...]}.
func decodeRecords(data []byte) ([]model.ScanRecord, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("request body is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))

	var records []model.ScanRecord
	switch trimmed[0] {
	case '[':
		if err := dec.Decode(&records); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
	case '{':
		var env struct {
			Items []model.ScanRecord `json:"items"`
		}
		if err := dec.Decode(&env); err != nil {
			return nil, fmt.Errorf("invalid JSON object: %w", err)
		}
		records = env.Items
	default:
		return nil, errors.New("body must be a JSON array or an object with an items array")
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	return records, nil
}

func ensureEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("unexpected trailing data after JSON body")
	}
	return nil
}

type errorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: apiError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type requestIDKey struct{}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		attrs := []any{
			"request_id", requestIDFrom(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", sw.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
		}
		// Container health probes every few seconds would otherwise flood logs.
		if strings.HasPrefix(r.URL.Path, "/health") {
			s.logger.Debug("http request", attrs...)
		} else {
			s.logger.Info("http request", attrs...)
		}
	})
}

func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered",
					"request_id", requestIDFrom(r.Context()),
					"panic", fmt.Sprint(rec),
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
