package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeEmptyDir(t *testing.T) {
	root := t.TempDir()
	report, err := Analyze(root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.LooksLikeMiniProgram {
		t.Fatal("empty dir should not look like miniprogram")
	}
	if report.Status == StatusOK {
		t.Fatal("expected non-ok status")
	}
}

func TestAnalyzePartialArtifacts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.json"), []byte(`{"pages":["pages/index"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pages", "index.js"), []byte(`Page({})`), 0644); err != nil {
		t.Fatal(err)
	}
	gwx := filepath.Join(root, ".gwxapkg")
	if err := os.MkdirAll(gwx, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gwx, "api_endpoint_map.json"), []byte(`{"endpoints":[{"id":"1"}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeAndWrite(root)
	if err != nil {
		t.Fatalf("AnalyzeAndWrite: %v", err)
	}
	if !report.LooksLikeMiniProgram {
		t.Fatal("expected miniprogram-like")
	}
	if report.HTTPEndpointCount != 1 {
		t.Fatalf("http endpoints=%d", report.HTTPEndpointCount)
	}
	if _, err := os.Stat(filepath.Join(gwx, "doctor_report.json")); err != nil {
		t.Fatalf("doctor json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(gwx, "doctor_report.md")); err != nil {
		t.Fatalf("doctor md missing: %v", err)
	}
}
