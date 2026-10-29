// Package config loads and validates the server configuration.
//
// The file holds no secrets. Each account names a client-secret file, which
// Load checks only by path; the secret contents are never read here and
// never appear in errors.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Config is the top-level server configuration. Every field is required;
// nothing defaults to a listening or exposed state.
type Config struct {
	Listen    string    `json:"listen"`
	PublicURL string    `json:"public_url"`
	DataDir   string    `json:"data_dir"`
	Accounts  []Account `json:"accounts"`
}

// Account describes one Olist account, an independent tenant.
type Account struct {
	ID               string `json:"id"`
	DisplayName      string `json:"display_name"`
	ClientID         string `json:"client_id"`
	ClientSecretFile string `json:"client_secret_file"`
	ReadsPerMinute   int    `json:"reads_per_minute"`
}

var accountIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse validates configuration JSON. Unknown fields and trailing data are
// rejected so that misspelled keys fail loudly. All validation problems are
// reported together.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("parse config: unexpected data after the JSON object")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks every field and returns all problems joined together.
func (c *Config) Validate() error {
	var errs []error

	if c.Listen == "" {
		errs = append(errs, errors.New("listen: required"))
	} else if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen: must be host:port: %v", err))
	}

	errs = append(errs, validatePublicURL(c.PublicURL)...)

	if strings.TrimSpace(c.DataDir) == "" {
		errs = append(errs, errors.New("data_dir: required"))
	}

	if len(c.Accounts) == 0 {
		errs = append(errs, errors.New("accounts: at least one account is required"))
	}
	seen := make(map[string]int, len(c.Accounts))
	for i := range c.Accounts {
		a := &c.Accounts[i]
		label := fmt.Sprintf("accounts[%d]", i)
		if a.ID != "" {
			label = fmt.Sprintf("accounts[%d] (%s)", i, a.ID)
		}
		errs = append(errs, validateAccount(label, a)...)
		if a.ID != "" && accountIDPattern.MatchString(a.ID) {
			if first, dup := seen[a.ID]; dup {
				errs = append(errs, fmt.Errorf("%s: id %q duplicates accounts[%d]", label, a.ID, first))
			} else {
				seen[a.ID] = i
			}
		}
	}

	return errors.Join(errs...)
}

func validatePublicURL(raw string) []error {
	if raw == "" {
		return []error{errors.New("public_url: required")}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return []error{fmt.Errorf("public_url: invalid URL: %v", err)}
	}
	var errs []error
	if u.Scheme != "https" {
		errs = append(errs, errors.New("public_url: scheme must be https"))
	}
	if u.Host == "" || u.Hostname() == "" {
		errs = append(errs, errors.New("public_url: host is required"))
	}
	if u.User != nil {
		errs = append(errs, errors.New("public_url: must not contain user information"))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, errors.New("public_url: must not contain a query or fragment"))
	}
	return errs
}

func validateAccount(label string, a *Account) []error {
	var errs []error
	if a.ID == "" {
		errs = append(errs, fmt.Errorf("%s: id: required", label))
	} else if !accountIDPattern.MatchString(a.ID) {
		errs = append(errs, fmt.Errorf("%s: id: only ASCII letters, digits, '-' and '_' are allowed", label))
	}
	if strings.TrimSpace(a.DisplayName) == "" {
		errs = append(errs, fmt.Errorf("%s: display_name: required", label))
	}
	if a.ClientID == "" {
		errs = append(errs, fmt.Errorf("%s: client_id: required", label))
	}
	if a.ClientSecretFile == "" {
		errs = append(errs, fmt.Errorf("%s: client_secret_file: required", label))
	} else if !filepath.IsAbs(a.ClientSecretFile) {
		errs = append(errs, fmt.Errorf("%s: client_secret_file: must be an absolute path", label))
	}
	if a.ReadsPerMinute <= 0 {
		errs = append(errs, fmt.Errorf("%s: reads_per_minute: must be positive", label))
	}
	return errs
}
