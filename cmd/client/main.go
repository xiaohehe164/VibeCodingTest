// Command client reads a local JSON file of scan records, sends them to the
// fingerprinting server, and renders the identification results.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"banner-fingerprint/internal/model"
)

const maxResponseBytes = 64 << 20

type envelope struct {
	Items []model.ScanRecord `json:"items"`
}

func main() {
	serverURL := flag.String("server", envString("SERVER_URL", "http://localhost:8080"),
		"fingerprint server base URL")
	inputFile := flag.String("input", envString("INPUT_FILE", "testdata/input.json"),
		"path to the JSON file containing scan records")
	format := flag.String("format", envString("OUTPUT_FORMAT", "table"),
		"output format: table or json")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP request timeout")
	flag.Parse()

	if err := run(*serverURL, *inputFile, *format, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(serverURL, inputFile, format string, timeout time.Duration) error {
	if format != "table" && format != "json" {
		return fmt.Errorf("unsupported format %q (want table or json)", format)
	}

	records, err := readRecords(inputFile)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("no scan records found")
		return nil
	}

	results, err := fingerprint(serverURL, records, timeout)
	if err != nil {
		return err
	}
	if len(results) != len(records) {
		fmt.Fprintf(os.Stderr, "warning: sent %d records but received %d results\n", len(records), len(results))
	}

	switch format {
	case "json":
		if err := printJSON(results); err != nil {
			return err
		}
	default:
		printTable(results)
	}
	return nil
}

func readRecords(path string) ([]model.ScanRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input %q: %w", path, err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input file %q is empty", path)
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var records []model.ScanRecord
	switch trimmed[0] {
	case '[':
		if err := dec.Decode(&records); err != nil {
			return nil, fmt.Errorf("parse input as JSON array: %w", err)
		}
	case '{':
		var env envelope
		if err := dec.Decode(&env); err != nil {
			return nil, fmt.Errorf("parse input as JSON object: %w", err)
		}
		records = env.Items
	default:
		return nil, fmt.Errorf("input must be a JSON array or an object with an items array")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing data in input file")
	}
	return records, nil
}

func fingerprint(serverURL string, records []model.ScanRecord, timeout time.Duration) ([]model.Fingerprint, error) {
	payload, err := json.Marshal(records)
	if err != nil {
		return nil, fmt.Errorf("encode records: %w", err)
	}

	endpoint := strings.TrimRight(serverURL, "/") + "/fingerprint"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "banner-fingerprint-client/1.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read server response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, errorMessage(body))
	}

	var results []model.Fingerprint
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("decode server response: %w", err)
	}
	return results, nil
}

func errorMessage(body []byte) string {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Error.Message != "" {
		return payload.Error.Message
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	return text
}

func printTable(results []model.Fingerprint) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	unknown := 0
	for _, r := range results {
		if r.Protocol == model.UnknownProtocol {
			unknown++
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			dash(r.IP), r.Port, dash(r.Protocol), dash(r.Product),
			dash(r.Version), dash(r.OSHint), r.Confidence)
	}
	w.Flush()
	fmt.Printf("\nTotal: %d   Identified: %d   Unknown: %d\n", len(results), len(results)-unknown, unknown)
}

func printJSON(results []model.Fingerprint) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
