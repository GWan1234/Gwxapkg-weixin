package configfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProjectConfig(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	content := "rule_tier: high\nbase_url: https://api.example.com\npostman: true\n"
	if err := os.WriteFile(filepath.Join(dir, ".gwxapkg.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if path == "" {
		t.Fatal("expected config path")
	}
	if cfg.RuleTier != "high" {
		t.Fatalf("rule_tier=%s", cfg.RuleTier)
	}
	if cfg.BaseURL != "https://api.example.com" {
		t.Fatalf("base_url=%s", cfg.BaseURL)
	}
	if !Bool(cfg.Postman, false) {
		t.Fatal("postman should be true")
	}
}
