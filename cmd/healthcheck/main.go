// Command healthcheck is a tiny static probe used by Docker HEALTHCHECK.
// It exists because the runtime image is "scratch" and therefore has no shell,
// curl or wget.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	url := os.Getenv("HEALTH_URL")
	if strings.TrimSpace(url) == "" {
		url = "http://127.0.0.1:8080/health"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		fmt.Fprintf(os.Stderr, "healthcheck: unexpected body: %s\n", strings.TrimSpace(string(body)))
		os.Exit(1)
	}
}
