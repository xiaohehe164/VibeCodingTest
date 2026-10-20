package fingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"banner-fingerprint/internal/model"
)

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := Load(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if eng.RuleCount() == 0 {
		t.Fatal("no rules loaded")
	}
	return eng
}

func TestIdentifySampleData(t *testing.T) {
	eng := loadTestEngine(t)

	tests := []struct {
		name       string
		rec        model.ScanRecord
		protocol   string
		product    string
		version    string
		osHint     string
		confidence float64
	}{
		{
			name: "openssh ubuntu", rec: model.ScanRecord{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			protocol: "SSH", product: "OpenSSH", version: "8.9p1", osHint: "Ubuntu", confidence: 0.95,
		},
		{
			name: "nginx", rec: model.ScanRecord{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			protocol: "HTTP", product: "nginx", version: "1.24.0", confidence: 0.9,
		},
		{
			name: "apache", rec: model.ScanRecord{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
			protocol: "HTTP", product: "Apache", version: "2.4.57", confidence: 0.9,
		},
		{
			name: "mysql 8 binary handshake", rec: model.ScanRecord{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"},
			protocol: "MySQL", product: "MySQL", version: "8.0.32", confidence: 0.9,
		},
		{
			name: "redis error", rec: model.ScanRecord{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"},
			protocol: "Redis", product: "Redis", confidence: 0.7,
		},
		{
			name: "proftpd", rec: model.ScanRecord{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			protocol: "FTP", product: "ProFTPD", version: "1.3.7", confidence: 0.9,
		},
		{
			name: "jetty", rec: model.ScanRecord{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
			protocol: "HTTP", product: "Jetty", version: "9.4.51", confidence: 0.85,
		},
		{
			name: "openssh debian", rec: model.ScanRecord{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"},
			protocol: "SSH", product: "OpenSSH", version: "9.3", osHint: "Debian", confidence: 0.95,
		},
		{
			name: "nginx ubuntu", rec: model.ScanRecord{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"},
			protocol: "HTTP", product: "nginx", version: "1.18.0", osHint: "Ubuntu", confidence: 0.9,
		},
		{
			name: "apache ubuntu", rec: model.ScanRecord{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"},
			protocol: "HTTP", product: "Apache", version: "2.4.41", osHint: "Ubuntu", confidence: 0.9,
		},
		{
			name: "mysql 5.7", rec: model.ScanRecord{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"},
			protocol: "MySQL", product: "MySQL", version: "5.7.42", confidence: 0.9,
		},
		{
			name: "redis pong", rec: model.ScanRecord{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"},
			protocol: "Redis", product: "Redis", confidence: 0.85,
		},
		{
			name: "vsftpd", rec: model.ScanRecord{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"},
			protocol: "FTP", product: "vsftpd", version: "3.0.5", confidence: 0.9,
		},
		{
			name: "nginx 8443", rec: model.ScanRecord{IP: "1.2.3.17", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"},
			protocol: "HTTP", product: "nginx", version: "1.25.3", confidence: 0.9,
		},
		{
			name: "openssh 1.99", rec: model.ScanRecord{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"},
			protocol: "SSH", product: "OpenSSH", version: "4.3", confidence: 0.95,
		},
		{
			name: "tls handshake escaped", rec: model.ScanRecord{IP: "1.2.3.19", Port: 9999, Banner: `\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`},
			protocol: "TLS", confidence: 0.85,
		},
		{
			name: "iis", rec: model.ScanRecord{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
			protocol: "HTTP", product: "Microsoft-IIS", version: "10.0", confidence: 0.85,
		},
		{
			name: "redis noauth", rec: model.ScanRecord{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."},
			protocol: "Redis", product: "Redis", confidence: 0.85,
		},
		{
			name: "pure-ftpd", rec: model.ScanRecord{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"},
			protocol: "FTP", product: "Pure-FTPd", confidence: 0.85,
		},
		{
			name: "unknown", rec: model.ScanRecord{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"},
			protocol: "unknown", confidence: 0,
		},
		{
			name: "mysql literal escapes", rec: model.ScanRecord{IP: "1.2.3.24", Port: 3306, Banner: `J\x00\x00\x00\n8.0.33\x00`},
			protocol: "MySQL", product: "MySQL", version: "8.0.33", confidence: 0.9,
		},
		{
			name: "postfix", rec: model.ScanRecord{IP: "1.2.3.25", Port: 25, Banner: "220 mail.example.com ESMTP Postfix"},
			protocol: "SMTP", product: "Postfix", confidence: 0.9,
		},
		{
			name: "dovecot imap", rec: model.ScanRecord{IP: "1.2.3.26", Port: 143, Banner: "* OK [CAPABILITY IMAP4rev1] Dovecot ready."},
			protocol: "IMAP", product: "Dovecot", confidence: 0.9,
		},
		{
			name: "vnc", rec: model.ScanRecord{IP: "1.2.3.27", Port: 5900, Banner: "RFB 003.008\n"},
			protocol: "VNC", product: "VNC", version: "003.008", confidence: 0.95,
		},
		{
			name: "apache coyote", rec: model.ScanRecord{IP: "1.2.3.28", Port: 8080, Banner: "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1"},
			protocol: "HTTP", product: "Apache Tomcat", version: "1.1", confidence: 0.85,
		},
		{
			name: "jetty parentheses", rec: model.ScanRecord{IP: "1.2.3.35", Port: 8080, Banner: "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51)"},
			protocol: "HTTP", product: "Jetty", version: "9.4.51", confidence: 0.85,
		},
		{
			name: "mysql prefixed handshake", rec: model.ScanRecord{IP: "1.2.3.36", Port: 3306, Banner: "PREFIX\x00\x00\x00\n8.0.36\x00"},
			protocol: "MySQL", product: "MySQL", version: "8.0.36", confidence: 0.75,
		},
		{
			name: "redis info", rec: model.ScanRecord{IP: "1.2.3.29", Port: 6379, Banner: "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone"},
			protocol: "Redis", product: "Redis", version: "7.2.4", confidence: 0.95,
		},
		{
			name: "empty banner", rec: model.ScanRecord{IP: "1.2.3.30", Port: 1234, Banner: ""},
			protocol: "unknown", confidence: 0,
		},
		{
			name: "http without server header", rec: model.ScanRecord{IP: "1.2.3.31", Port: 443, Banner: "HTTP/1.1 403 Forbidden\r\nContent-Length: 0"},
			protocol: "HTTP", confidence: 0.6,
		},
		{
			name: "mqtt connack", rec: model.ScanRecord{IP: "1.2.3.32", Port: 1883, Banner: `\x20\x02\x00\x00`},
			protocol: "MQTT", confidence: 0.8,
		},
		{
			name: "memcached version", rec: model.ScanRecord{IP: "1.2.3.33", Port: 11211, Banner: "VERSION 1.6.21"},
			protocol: "Memcached", product: "Memcached", version: "1.6.21", confidence: 0.9,
		},
		{
			name: "telnet", rec: model.ScanRecord{IP: "1.2.3.34", Port: 23, Banner: "Ubuntu 22.04 login:"},
			protocol: "Telnet", confidence: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eng.Identify(tt.rec)
			if got.Protocol != tt.protocol {
				t.Errorf("protocol = %q, want %q", got.Protocol, tt.protocol)
			}
			if got.Product != tt.product {
				t.Errorf("product = %q, want %q", got.Product, tt.product)
			}
			if got.Version != tt.version {
				t.Errorf("version = %q, want %q", got.Version, tt.version)
			}
			if got.OSHint != tt.osHint {
				t.Errorf("os_hint = %q, want %q", got.OSHint, tt.osHint)
			}
			if got.Confidence != tt.confidence {
				t.Errorf("confidence = %v, want %v", got.Confidence, tt.confidence)
			}
			if got.IP != tt.rec.IP || got.Port != tt.rec.Port {
				t.Errorf("identity not echoed: got %s:%d", got.IP, got.Port)
			}
		})
	}
}

func TestIdentifyEscapedHTTP(t *testing.T) {
	eng := loadTestEngine(t)
	// Banners exported with literal backslash escapes (not decoded JSON).
	got := eng.Identify(model.ScanRecord{
		IP: "10.0.0.1", Port: 80,
		Banner: `HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Length: 0`,
	})
	if got.Protocol != "HTTP" || got.Product != "nginx" || got.Version != "1.18.0" || got.OSHint != "Ubuntu" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestIdentifyDoesNotPanicOnHostileInput(t *testing.T) {
	eng := loadTestEngine(t)
	inputs := []string{
		"",
		"\x00\x00\x00",
		"HTTP/1.1",
		"SSH-",
		"220",
		"+++",
		"J\x00",
		"\x16\x03",
	}
	for _, in := range inputs {
		got := eng.Identify(model.ScanRecord{IP: "192.0.2.1", Port: 0, Banner: in})
		if got.Protocol == "" {
			t.Fatalf("empty protocol for input %q", in)
		}
	}
}

func TestUnescapeBanner(t *testing.T) {
	cases := map[string]string{
		`\x41\x42`:          "AB",
		`a\nb`:              "a\nb",
		`a\r\nb`:            "a\r\nb",
		`tab\tend`:          "tab\tend",
		`C:\\path`:          `C:\path`,
		`no escapes at all`: "no escapes at all",
		`bad\xZZ`:           `bad\xZZ`,
	}
	for in, want := range cases {
		if got := unescapeBanner(in); got != want {
			t.Errorf("unescapeBanner(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRulesAreDataDriven(t *testing.T) {
	dir := t.TempDir()
	ruleYAML := `rules:
  - id: custom-app
    protocol: CUSTOM
    product: MyApp
    version: '${v}'
    confidence: 0.99
    priority: 9999
    match:
      - type: regex
        pattern: '^CUSTOM/(?P<v>[0-9.]+)'
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(dir)
	if err != nil {
		t.Fatalf("load custom rules: %v", err)
	}
	got := eng.Identify(model.ScanRecord{IP: "192.0.2.10", Port: 4242, Banner: "CUSTOM/3.1.4"})
	if got.Protocol != "CUSTOM" || got.Product != "MyApp" || got.Version != "3.1.4" || got.Confidence != 0.99 {
		t.Fatalf("unexpected custom rule result: %+v", got)
	}
}

func TestInvalidRulesRejected(t *testing.T) {
	cases := map[string]string{
		"bad regex": `rules:
  - id: x
    protocol: X
    confidence: 0.5
    match:
      - type: regex
        pattern: '(['
`,
		"missing confidence": `rules:
  - id: x
    protocol: X
    match:
      - type: contains
        pattern: x
`,
		"unknown key": `rules:
  - id: x
    protocol: X
    confidence: 0.5
    typo_field: true
    match:
      - type: contains
        pattern: x
`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); err == nil {
				t.Fatal("expected invalid rule set to be rejected")
			}
		})
	}
}

func TestReloadKeepsOldSnapshotOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	valid := `rules:
  - id: first
    protocol: FIRST
    confidence: 0.9
    match:
      - type: prefix
        pattern: 'HELLO'
`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := eng.Identify(model.ScanRecord{Banner: "HELLO"}); got.Protocol != "FIRST" {
		t.Fatalf("got %q", got.Protocol)
	}

	invalid := `rules:
  - id: broken
    protocol: BROKEN
    confidence: 5
    match:
      - type: prefix
        pattern: 'HELLO'
`
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	if got := eng.Identify(model.ScanRecord{Banner: "HELLO"}); got.Protocol != "FIRST" {
		t.Fatalf("previous snapshot was lost, got %q", got.Protocol)
	}

	updated := `rules:
  - id: second
    protocol: SECOND
    confidence: 0.9
    match:
      - type: prefix
        pattern: 'HELLO'
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := eng.Identify(model.ScanRecord{Banner: "HELLO"}); got.Protocol != "SECOND" {
		t.Fatalf("got %q after reload", got.Protocol)
	}
}
