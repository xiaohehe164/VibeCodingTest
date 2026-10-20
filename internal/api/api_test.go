package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/model"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	eng, err := fingerprint.Load(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if cfg.Version == "" {
		cfg.Version = "test"
	}
	return New(eng, logger, cfg)
}

func doRequest(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t, Config{})
	rr := doRequest(t, srv.Handler(), http.MethodGet, "/health", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if got.Status != "ok" || got.Service != "banner-fingerprint" || got.Rules <= 0 {
		t.Fatalf("unexpected health: %+v", got)
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID header")
	}
}

func TestFingerprintBatchFromTestdata(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "..", "testdata", "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, Config{})
	rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", input)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var results []model.Fingerprint
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	if len(results) != 31 {
		t.Fatalf("got %d results, want 31", len(results))
	}

	first := results[0]
	if first.IP != "1.2.3.4" || first.Port != 22 || first.Protocol != "SSH" ||
		first.Product != "OpenSSH" || first.Version != "8.9p1" ||
		first.OSHint != "Ubuntu" || first.Confidence != 0.95 {
		t.Fatalf("unexpected ssh result: %+v", first)
	}
	if results[19].Protocol != model.UnknownProtocol {
		t.Fatalf("QUIT banner should be unknown, got %+v", results[19])
	}
	if results[26].Protocol != model.UnknownProtocol {
		t.Fatalf("empty banner should be unknown, got %+v", results[26])
	}
}

func TestFingerprintEnvelope(t *testing.T) {
	body := []byte(`{"items":[{"ip":"10.0.0.1","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}]}`)
	srv := newTestServer(t, Config{})
	rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var results []model.Fingerprint
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Product != "nginx" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestFingerprintEmptyArray(t *testing.T) {
	srv := newTestServer(t, Config{})
	rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", []byte(`[]`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := rr.Body.String(); got != "[]\n" {
		t.Fatalf("body = %q, want []", got)
	}
}

func TestFingerprintRejectsMalformedJSON(t *testing.T) {
	srv := newTestServer(t, Config{})
	for _, body := range []string{``, `{`, `"banner"`, `[{"ip": }]`, `[] trailing`} {
		rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", []byte(body))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rr.Code)
		}
		var payload errorBody
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
			t.Errorf("body %q: error response is not JSON: %v", body, err)
		}
	}
}

func TestFingerprintBatchLimit(t *testing.T) {
	srv := newTestServer(t, Config{MaxBatch: 1})
	body := []byte(`[{"ip":"a","port":1,"banner":"x"},{"ip":"b","port":2,"banner":"y"}]`)
	rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var payload errorBody
	_ = json.Unmarshal(rr.Body.Bytes(), &payload)
	if payload.Error.Code != "batch_too_large" {
		t.Fatalf("error code = %q", payload.Error.Code)
	}
}

func TestFingerprintBodyLimit(t *testing.T) {
	srv := newTestServer(t, Config{MaxBodyBytes: 16})
	body := []byte(`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}]`)
	rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", body)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t, Config{})
	rr := doRequest(t, srv.Handler(), http.MethodGet, "/fingerprint", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestUnknownBannerDoesNotFail(t *testing.T) {
	srv := newTestServer(t, Config{})
	body := []byte(`[{"ip":"192.0.2.5","port":9999,"banner":"totally random junk"}]`)
	rr := doRequest(t, srv.Handler(), http.MethodPost, "/fingerprint", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var results []model.Fingerprint
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Protocol != model.UnknownProtocol || results[0].Confidence != 0 {
		t.Fatalf("unexpected result: %+v", results)
	}
}
