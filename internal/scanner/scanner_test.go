package scanner

import (
	"regexp"
	"strings"
	"testing"
)

func TestParseRuleTierSpec(t *testing.T) {
	tests := []struct {
		spec string
		want []string
	}{
		{"", nil},
		{"all", nil},
		{"*", nil},
		{"high", []string{TierCritical, TierHigh}},
		{"medium", []string{TierCritical, TierHigh, TierMedium}},
		{"critical,noise", []string{TierCritical, TierNoise}},
		{"high,medium", []string{TierHigh, TierMedium}},
	}
	for _, tt := range tests {
		got := ParseRuleTierSpec(tt.spec)
		if len(got) != len(tt.want) {
			t.Fatalf("spec %q: got %v want %v", tt.spec, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("spec %q: got %v want %v", tt.spec, got, tt.want)
			}
		}
	}
}

func TestGetTierNoiseAndCritical(t *testing.T) {
	if got := GetTier("email"); got != TierNoise {
		t.Fatalf("email tier = %s, want noise", got)
	}
	if got := GetTier("private_key_rsa"); got != TierCritical {
		t.Fatalf("private_key_rsa tier = %s, want critical", got)
	}
	if got := GetTier("aws_access_key_id"); got != TierCritical && got != TierHigh {
		t.Fatalf("aws_access_key_id tier = %s, want critical/high", got)
	}
}

func TestShouldScanPath(t *testing.T) {
	if !ShouldScanPath("pages/index.js") {
		t.Fatal("js should scan")
	}
	if ShouldScanPath("assets/logo.png") {
		t.Fatal("png should skip")
	}
	if ShouldScanPath(".gwxapkg/api_map.json") {
		t.Fatal(".gwxapkg should skip")
	}
}

func TestScanFileTierFilter(t *testing.T) {
	CompiledRules = []*CompiledRule{
		{
			ID:         "email",
			Pattern:    regexp.MustCompile(`\b[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
			Category:   "contact",
			Confidence: "low",
			Tier:       TierNoise,
		},
		{
			ID:         "aws_access_key_id",
			Pattern:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Category:   "cloud",
			Confidence: "high",
			Tier:       TierCritical,
		},
	}

	// 避免 example/placeholder 误报过滤
	content := []byte("contact ops@corp-mail.cn and key AKIAIOSFODNN7TESTKEY\n")
	collectorAll := NewCollector("test")
	if err := ScanFileWithOptions("app.js", content, collectorAll, DefaultScanOptions()); err != nil {
		t.Fatalf("scan all: %v", err)
	}
	reportAll := collectorAll.GenerateReport()
	if reportAll.Summary.TotalMatches < 2 {
		t.Fatalf("expected both email and aws hits, got %d items=%v", reportAll.Summary.TotalMatches, reportAll.Items)
	}

	collectorHigh := NewCollector("test")
	opts := ScanOptions{
		Tiers:        ParseRuleTierSpec("high"),
		MaxLineBytes: DefaultMaxLineBytes,
		ExtractAPI:   true,
	}
	if err := ScanFileWithOptions("app.js", content, collectorHigh, opts); err != nil {
		t.Fatalf("scan high: %v", err)
	}
	reportHigh := collectorHigh.GenerateReport()
	for _, item := range reportHigh.Items {
		if item.RuleID == "email" {
			t.Fatalf("email should be filtered by -rule-tier=high")
		}
	}
	foundAWS := false
	for _, item := range reportHigh.Items {
		if item.RuleID == "aws_access_key_id" {
			foundAWS = true
		}
	}
	if !foundAWS {
		t.Fatalf("expected aws key hit under high tier, items=%v", reportHigh.Items)
	}
}

func TestAPIExtractCheapPrecheck(t *testing.T) {
	// 无 request 特征，不应提取
	if got := ExtractAPIEndpointsFromText("a.js", "const x = 1; Math.random();"); len(got) != 0 {
		t.Fatalf("expected no endpoints, got %d", len(got))
	}

	src := `wx.request({ url: "/api/user/login", method: "POST" })`
	got := ExtractAPIEndpointsFromText("service.js", src)
	if len(got) == 0 {
		t.Fatal("expected at least one endpoint")
	}
	found := false
	for _, ep := range got {
		if strings.Contains(ep.RawURL, "/api/user/login") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /api/user/login, got %#v", got)
	}
}

func TestExtractAPIEndpointsASTBaseConcat(t *testing.T) {
	src := `
const base = "https://api.example.com";
function load() {
  wx.request({ url: base + "/v1/user", method: "GET" });
}
`
	got := ExtractAPIEndpointsAST("svc.js", src)
	found := false
	for _, ep := range got {
		if strings.Contains(ep.RawURL, "/v1/user") && strings.Contains(ep.RawURL, "api.example.com") {
			found = true
			if ep.Method != "GET" {
				t.Fatalf("method=%s", ep.Method)
			}
		}
	}
	if !found {
		t.Fatalf("expected base+path endpoint, got %#v", got)
	}
}

func TestSkipNonTextExt(t *testing.T) {
	collector := NewCollector("test")
	CompiledRules = []*CompiledRule{
		{
			ID:         "email",
			Pattern:    regexp.MustCompile(`admin@example.com`),
			Category:   "contact",
			Confidence: "low",
			Tier:       TierNoise,
		},
	}
	if err := ScanFileWithOptions("logo.png", []byte("admin@example.com"), collector, DefaultScanOptions()); err != nil {
		t.Fatalf("scan png: %v", err)
	}
	if collector.GenerateReport().Summary.TotalMatches != 0 {
		t.Fatal("png content should not be scanned")
	}
}
