package fingerprint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"banner-fingerprint/internal/model"
)

// Engine evaluates scan records against an immutable, atomically-swappable
// rule snapshot. Reload builds a fresh snapshot and only publishes it if the
// whole rule set validates, so readers never observe partial rules.
type Engine struct {
	dir     string
	current atomic.Pointer[snapshot]
}

// Load compiles every rule in dir and returns a ready engine. Startup fails
// when no valid rules are available: running "healthy" without signatures
// would silently mark the entire estate as unknown.
func Load(dir string) (*Engine, error) {
	e := &Engine{dir: dir}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload re-reads the rules directory. On validation failure the previous
// snapshot stays active and the error is returned to the caller.
func (e *Engine) Reload() error {
	snap, err := loadSnapshot(e.dir)
	if err != nil {
		return err
	}
	e.current.Store(snap)
	return nil
}

// RuleCount returns the number of active rules.
func (e *Engine) RuleCount() int {
	if snap := e.current.Load(); snap != nil {
		return len(snap.rules)
	}
	return 0
}

// RuleFiles returns the rule file names backing the active snapshot.
func (e *Engine) RuleFiles() []string {
	snap := e.current.Load()
	if snap == nil {
		return nil
	}
	return append([]string(nil), snap.files...)
}

// Directory returns the directory the engine loads signatures from.
func (e *Engine) Directory() string { return e.dir }

// Identify returns the best fingerprint for one record. It never panics on
// malformed or empty banners; unmatched input is reported as "unknown".
func (e *Engine) Identify(rec model.ScanRecord) model.Fingerprint {
	out := model.NewUnknown(rec)
	snap := e.current.Load()
	if snap == nil {
		return out
	}

	variants := bannerVariants(rec.Banner)
	for _, cr := range snap.rules {
		for _, banner := range variants {
			groups, ok := cr.matches(banner, rec.IP, rec.Port)
			if !ok {
				continue
			}
			out.Protocol = cr.rule.Protocol
			out.Product = sanitize(render(cr.rule.Product, groups))
			out.Version = sanitize(render(cr.rule.Version, groups))
			out.OSHint = sanitize(render(cr.rule.OSHint, groups))
			out.Confidence = cr.rule.Confidence
			return out
		}
	}
	return out
}

// IdentifyBatch fingerprints every record, preserving input order.
func (e *Engine) IdentifyBatch(records []model.ScanRecord) []model.Fingerprint {
	results := make([]model.Fingerprint, len(records))
	for i, rec := range records {
		results[i] = e.Identify(rec)
	}
	return results
}

func (cr *compiledRule) matches(banner, ip string, port int) (map[string]string, bool) {
	groups := make(map[string]string, 4)
	for i, cond := range cr.rule.Match {
		ok := false
		switch cond.Type {
		case "regex":
			subject, valid := conditionSubject(cond.Field, banner, ip)
			if !valid {
				return nil, false
			}
			re := cr.regexps[i]
			if m := re.FindStringSubmatch(subject); m != nil {
				ok = true
				names := re.SubexpNames()
				for j := 1; j < len(m); j++ {
					if names[j] != "" && m[j] != "" {
						groups[names[j]] = m[j]
					}
				}
			}
		case "contains":
			subject, valid := conditionSubject(cond.Field, banner, ip)
			if !valid {
				return nil, false
			}
			if cond.IgnoreCase {
				ok = strings.Contains(strings.ToLower(subject), strings.ToLower(cond.Pattern))
			} else {
				ok = strings.Contains(subject, cond.Pattern)
			}
		case "prefix":
			subject, valid := conditionSubject(cond.Field, banner, ip)
			if !valid {
				return nil, false
			}
			if cond.IgnoreCase {
				ok = strings.HasPrefix(strings.ToLower(subject), strings.ToLower(cond.Pattern))
			} else {
				ok = strings.HasPrefix(subject, cond.Pattern)
			}
		case "port_in":
			for _, p := range cond.Ports {
				if p == port {
					ok = true
					break
				}
			}
		}
		if cond.Negate {
			ok = !ok
		}
		if !ok {
			return nil, false
		}
	}
	return groups, true
}

func conditionSubject(field, banner, ip string) (string, bool) {
	switch field {
	case "", "banner":
		return banner, true
	case "ip":
		return ip, true
	default:
		return "", false
	}
}

var placeholderRE = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

// render substitutes ${group} placeholders with captured values. Unknown
// groups expand to an empty string, which is the desired "not detected"
// representation for optional fields.
func render(tpl string, groups map[string]string) string {
	if !strings.Contains(tpl, "${") {
		return tpl
	}
	return placeholderRE.ReplaceAllStringFunc(tpl, func(ph string) string {
		// ph is "${name}".
		return groups[ph[2:len(ph)-1]]
	})
}

// sanitize keeps output fields bounded and free of control characters so a
// hostile banner cannot corrupt logs or downstream consumers.
func sanitize(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 128 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// bannerVariants returns the textual forms a rule may be matched against.
// Scanners and JSON authors disagree on whether binary bytes are stored raw or
// as literal "\x00"/"\r\n" escapes, so both are supported. Outer whitespace is
// also trimmed because many captures include incidental leading CR/LF bytes.
func bannerVariants(banner string) []string {
	variants := []string{banner}
	if unescaped := unescapeBanner(banner); unescaped != banner {
		variants = append(variants, unescaped)
	}
	for _, v := range append([]string(nil), variants...) {
		trimmed := strings.Trim(v, "\x00\r\n\t ")
		if trimmed == "" || containsString(variants, trimmed) {
			continue
		}
		variants = append(variants, trimmed)
	}
	return variants
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// unescapeBanner decodes the escape notations commonly found in exported
// scan data: \xNN, \n, \r, \t, \0, \a, \b, \f, \v and \\.
func unescapeBanner(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'x':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 3
					continue
				}
			}
			b.WriteByte(s[i])
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case '0':
			b.WriteByte(0)
			i++
		case 'a':
			b.WriteByte('\a')
			i++
		case 'b':
			b.WriteByte('\b')
			i++
		case 'f':
			b.WriteByte('\f')
			i++
		case 'v':
			b.WriteByte('\v')
			i++
		case '\\':
			b.WriteByte('\\')
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// SnapshotInfo is a small, immutable view used by health/ops endpoints.
type SnapshotInfo struct {
	Rules int
	Files []string
}

// Info returns metadata about the currently active rule snapshot.
func (e *Engine) Info() SnapshotInfo {
	snap := e.current.Load()
	if snap == nil {
		return SnapshotInfo{}
	}
	return SnapshotInfo{Rules: len(snap.rules), Files: append([]string(nil), snap.files...)}
}

// String is useful in startup logs.
func (e *Engine) String() string {
	info := e.Info()
	return fmt.Sprintf("rules=%d files=%d dir=%s", info.Rules, len(info.Files), e.dir)
}
