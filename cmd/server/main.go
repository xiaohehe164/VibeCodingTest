// Command server starts the banner fingerprinting HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"banner-fingerprint/internal/api"
	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/version"
)

func main() {
	logger := newLogger()

	rulesDir := envString("RULES_DIR", "/app/rules")
	engine, err := fingerprint.Load(rulesDir)
	if err != nil {
		logger.Error("failed to load fingerprint rules", "dir", rulesDir, "error", err)
		os.Exit(1)
	}

	maxBatch, err := envInt("MAX_BATCH_SIZE", 10000)
	if err != nil {
		logger.Error("invalid MAX_BATCH_SIZE", "error", err)
		os.Exit(1)
	}
	maxBody, err := envInt64("MAX_BODY_BYTES", 16<<20)
	if err != nil {
		logger.Error("invalid MAX_BODY_BYTES", "error", err)
		os.Exit(1)
	}

	addr := envString("LISTEN_ADDR", ":8080")
	handler := api.New(engine, logger, api.Config{
		MaxBatch:     maxBatch,
		MaxBodyBytes: maxBody,
		Version:      version.Version,
	}).Handler()

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("http server started",
			"addr", addr,
			"version", version.Version,
			"rules", engine.RuleCount(),
			"rule_files", len(engine.RuleFiles()),
			"rules_dir", rulesDir,
		)
		serveErr <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, gracefulSignals()...)
	defer signal.Stop(sigCh)

	for {
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("http server failed", "error", err)
				os.Exit(1)
			}
			return
		case sig := <-sigCh:
			if isReloadSignal(sig) {
				logger.Info("reloading fingerprint rules", "dir", rulesDir)
				if err := engine.Reload(); err != nil {
					logger.Error("rule reload failed; previous rules remain active", "error", err)
				} else {
					logger.Info("fingerprint rules reloaded", "rules", engine.RuleCount())
				}
				continue
			}

			logger.Info("shutting down http server", "signal", sig.String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := httpServer.Shutdown(ctx)
			cancel()
			if err != nil {
				logger.Error("graceful shutdown failed", "error", err)
				os.Exit(1)
			}
			logger.Info("http server stopped")
			return
		}
	}
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(envString("LOG_LEVEL", "info")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).
		With("service", "banner-fingerprint-server")
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", key, raw)
	}
	return v, nil
}

func envInt64(key string, fallback int64) (int64, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", key, raw)
	}
	return v, nil
}
