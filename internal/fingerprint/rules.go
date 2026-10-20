// Package fingerprint implements a data-driven banner fingerprint engine.
//
// Detection knowledge lives entirely in external YAML files (see /rules).
// The Go code only knows how to evaluate the generic rule schema, which keeps
// signatures decoupled from releases of the binary.
package fingerprint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is a single detection signature. All conditions in Match must succeed
// for the rule to fire. Named capture groups from regex conditions are made
// available to the product/version/os_hint templates as ${name}.
type Rule struct {
	ID          string      `yaml:"id"`
	Description string      `yaml:"description,omitempty"`
	Protocol    string      `yaml:"protocol"`
	Product     string      `yaml:"product,omitempty"`
	Version     string      `yaml:"version,omitempty"`
	OSHint      string      `yaml:"os_hint,omitempty"`
	Confidence  float64     `yaml:"confidence"`
	Priority    int         `yaml:"priority,omitempty"`
	Match       []Condition `yaml:"match"`
}

// Condition is one predicate over a banner, the source IP, or the port.
type Condition struct {
	// Field selects the text subject: "banner" (default) or "ip".
	Field string `yaml:"field,omitempty"`
	// Type is one of: regex, contains, prefix, port_in.
	Type string `yaml:"type"`
	// Pattern is the regex/text used by regex/contains/prefix.
	Pattern string `yaml:"pattern,omitempty"`
	// Ports is the accepted port list for port_in.
	Ports []int `yaml:"ports,omitempty"`
	// IgnoreCase applies to contains/prefix.
	IgnoreCase bool `yaml:"ignore_case,omitempty"`
	// Negate inverts the predicate.
	Negate bool `yaml:"negate,omitempty"`
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

type compiledRule struct {
	rule    Rule
	regexps map[int]*regexp.Regexp
}

type snapshot struct {
	rules []*compiledRule
	files []string
}

func loadSnapshot(dir string) (*snapshot, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("rules directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules path %q is not a directory", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, entry.Name())
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.yaml/*.yml rule files found in %q", dir)
	}
	sort.Strings(files)

	snap := &snapshot{files: files}
	seen := make(map[string]string)
	for _, name := range files {
		path := filepath.Join(dir, name)
		rules, err := loadRuleFile(path)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate rule id %q (already defined in %s)", name, r.ID, prev)
			}
			seen[r.ID] = name
			cr, err := compileRule(r)
			if err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", name, r.ID, err)
			}
			snap.rules = append(snap.rules, cr)
		}
	}
	if len(snap.rules) == 0 {
		return nil, errors.New("rule set is empty")
	}

	// Higher priority wins; confidence breaks ties; ID keeps ordering stable.
	sort.SliceStable(snap.rules, func(i, j int) bool {
		a, b := snap.rules[i].rule, snap.rules[j].rule
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.ID < b.ID
	})
	return snap, nil
}

func loadRuleFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rf ruleFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject misspelled keys instead of silently ignoring them
	if err := dec.Decode(&rf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty rule file", path)
		}
		return nil, fmt.Errorf("%s: parse yaml: %w", path, err)
	}
	return rf.Rules, nil
}

func compileRule(r Rule) (*compiledRule, error) {
	r.ID = strings.TrimSpace(r.ID)
	r.Protocol = strings.TrimSpace(r.Protocol)
	if r.ID == "" {
		return nil, errors.New("id is required")
	}
	if r.Protocol == "" {
		return nil, errors.New("protocol is required")
	}
	if len(r.Match) == 0 {
		return nil, errors.New("at least one match condition is required")
	}
	if !(r.Confidence > 0 && r.Confidence <= 1) {
		return nil, fmt.Errorf("confidence must be in (0, 1], got %v", r.Confidence)
	}

	cr := &compiledRule{rule: r, regexps: make(map[int]*regexp.Regexp, len(r.Match))}
	for i, cond := range r.Match {
		switch cond.Type {
		case "regex":
			if cond.Pattern == "" {
				return nil, fmt.Errorf("match[%d]: regex pattern is empty", i)
			}
			re, err := regexp.Compile(cond.Pattern)
			if err != nil {
				return nil, fmt.Errorf("match[%d]: invalid regex: %w", i, err)
			}
			cr.regexps[i] = re
		case "contains", "prefix":
			if cond.Pattern == "" {
				return nil, fmt.Errorf("match[%d]: pattern is empty", i)
			}
		case "port_in":
			if len(cond.Ports) == 0 {
				return nil, fmt.Errorf("match[%d]: ports is empty", i)
			}
			for _, p := range cond.Ports {
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("match[%d]: invalid port %d", i, p)
				}
			}
		default:
			return nil, fmt.Errorf("match[%d]: unsupported type %q", i, cond.Type)
		}
		switch cond.Field {
		case "", "banner", "ip":
		default:
			return nil, fmt.Errorf("match[%d]: unsupported field %q", i, cond.Field)
		}
	}
	return cr, nil
}
