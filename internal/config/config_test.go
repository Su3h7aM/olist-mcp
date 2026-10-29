package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		Listen:    "127.0.0.1:8080",
		PublicURL: "https://olist.example.com",
		DataDir:   "/var/lib/olist-mcp",
		Accounts: []Account{
			{ID: "primary", DisplayName: "Primary", ClientID: "cid-1", ClientSecretFile: "/run/secrets/primary", ReadsPerMinute: 140},
			{ID: "retail_2", DisplayName: "Retail 2", ClientID: "cid-2", ClientSecretFile: "/run/secrets/retail_2", ReadsPerMinute: 30},
		},
	}
}

func toJSON(t *testing.T, c Config) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseValidMultiAccount(t *testing.T) {
	cfg, err := Parse(toJSON(t, validConfig()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.PublicURL != "https://olist.example.com" || cfg.DataDir != "/var/lib/olist-mcp" {
		t.Fatalf("top-level fields = %+v", cfg)
	}
	if len(cfg.Accounts) != 2 {
		t.Fatalf("accounts = %d, want 2", len(cfg.Accounts))
	}
	if got := cfg.Accounts[1]; got.ID != "retail_2" || got.ReadsPerMinute != 30 || got.ClientSecretFile != "/run/secrets/retail_2" {
		t.Fatalf("second account = %+v", got)
	}
}

func TestParseAcceptsManyAccounts(t *testing.T) {
	c := validConfig()
	c.Accounts = nil
	for i := 0; i < 25; i++ {
		c.Accounts = append(c.Accounts, Account{
			ID:               fmt.Sprintf("acc-%02d", i),
			DisplayName:      "Account",
			ClientID:         "cid",
			ClientSecretFile: "/run/secrets/x",
			ReadsPerMinute:   60,
		})
	}
	if _, err := Parse(toJSON(t, c)); err != nil {
		t.Fatalf("Parse with 25 accounts: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		want   string
	}{
		{"missing listen", func(c *Config) { c.Listen = "" }, "listen: required"},
		{"listen without port", func(c *Config) { c.Listen = "127.0.0.1" }, "listen: must be host:port"},
		{"missing public_url", func(c *Config) { c.PublicURL = "" }, "public_url: required"},
		{"public_url http", func(c *Config) { c.PublicURL = "http://olist.example.com" }, "scheme must be https"},
		{"public_url no host", func(c *Config) { c.PublicURL = "https:///path" }, "host is required"},
		{"public_url with user", func(c *Config) { c.PublicURL = "https://user:pw@olist.example.com" }, "user information"},
		{"public_url with query", func(c *Config) { c.PublicURL = "https://olist.example.com/?x=1" }, "query or fragment"},
		{"public_url unparsable", func(c *Config) { c.PublicURL = "https://[::1" }, "invalid URL"},
		{"missing data_dir", func(c *Config) { c.DataDir = "  " }, "data_dir: required"},
		{"no accounts", func(c *Config) { c.Accounts = nil }, "at least one account"},
		{"missing account id", func(c *Config) { c.Accounts[0].ID = "" }, "id: required"},
		{"malformed account id space", func(c *Config) { c.Accounts[0].ID = "bad id" }, "only ASCII letters"},
		{"malformed account id dot", func(c *Config) { c.Accounts[0].ID = "a.b" }, "only ASCII letters"},
		{"non-ASCII account id", func(c *Config) { c.Accounts[0].ID = "conta-ção" }, "only ASCII letters"},
		{"duplicate account id", func(c *Config) { c.Accounts[1].ID = c.Accounts[0].ID }, "duplicates accounts[0]"},
		{"missing display_name", func(c *Config) { c.Accounts[0].DisplayName = " " }, "display_name: required"},
		{"missing client_id", func(c *Config) { c.Accounts[0].ClientID = "" }, "client_id: required"},
		{"missing client_secret_file", func(c *Config) { c.Accounts[0].ClientSecretFile = "" }, "client_secret_file: required"},
		{"relative client_secret_file", func(c *Config) { c.Accounts[0].ClientSecretFile = "secrets/primary" }, "must be an absolute path"},
		{"zero reads_per_minute", func(c *Config) { c.Accounts[0].ReadsPerMinute = 0 }, "reads_per_minute: must be positive"},
		{"negative reads_per_minute", func(c *Config) { c.Accounts[0].ReadsPerMinute = -5 }, "reads_per_minute: must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(&c)
			_, err := Parse(toJSON(t, c))
			if err == nil {
				t.Fatalf("Parse accepted invalid config; want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestValidationReportsAllProblemsTogether(t *testing.T) {
	c := Config{Accounts: []Account{{}}}
	err := c.Validate()
	if err == nil {
		t.Fatal("empty config accepted")
	}
	for _, want := range []string{"listen", "public_url", "data_dir", "id: required", "client_secret_file", "reads_per_minute"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("combined error missing %q: %v", want, err)
		}
	}
}

func TestParseRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	valid := toJSON(t, validConfig())

	withUnknown := strings.Replace(string(valid), `"listen"`, `"listn_addr":"x","listen"`, 1)
	if _, err := Parse([]byte(withUnknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: err = %v", err)
	}

	trailing := string(valid) + ` {}`
	if _, err := Parse([]byte(trailing)); err == nil || !strings.Contains(err.Error(), "unexpected data") {
		t.Fatalf("trailing data: err = %v", err)
	}

	if _, err := Parse([]byte(`{"listen":`)); err == nil {
		t.Fatal("truncated JSON accepted")
	}
}

func TestLoadReadsFileWithoutReadingSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "primary.secret")
	const secretValue = "super-secret-value-do-not-leak"
	if err := os.WriteFile(secret, []byte(secretValue), 0o600); err != nil {
		t.Fatal(err)
	}

	c := validConfig()
	c.Accounts[0].ClientSecretFile = secret
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, toJSON(t, c), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Accounts[0].ClientSecretFile != secret {
		t.Fatalf("secret path = %q", cfg.Accounts[0].ClientSecretFile)
	}

	// A missing secret file is not an error at load time: only the path is checked.
	c.Accounts[0].ClientSecretFile = filepath.Join(dir, "does-not-exist")
	if _, err := Parse(toJSON(t, c)); err != nil {
		t.Fatalf("Parse with absent secret file: %v", err)
	}

	// Errors must not echo secret contents.
	c.Accounts[0].ClientSecretFile = secret
	c.Accounts[0].ReadsPerMinute = 0
	_, err = Load(writeTemp(t, c))
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatal("error leaked secret contents")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func writeTemp(t *testing.T, c Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, toJSON(t, c), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
