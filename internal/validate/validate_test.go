package validate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/business"
)

func TestRunRequiresAuthorization(t *testing.T) {
	_, err := Run(Options{Dir: t.TempDir(), BaseURL: "https://example.com"})
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestRunDryRunAndLiveUnauth(t *testing.T) {
	// mock API server
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") == "" && r.URL.Path == "/api/app/order/detail" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{"orderId":"1","billCode":"STO123","mobile":"13800138000"}}`))
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, `{"msg":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	}))
	defer srv.Close()

	root := t.TempDir()
	gwx := filepath.Join(root, ".gwxapkg")
	if err := os.MkdirAll(gwx, 0755); err != nil {
		t.Fatal(err)
	}
	// minimal business surface
	surface := &business.SurfaceReport{
		SourceDir: root,
		Summary:   map[string]int{"idor": 1, "order": 1},
		Endpoints: []business.TaggedEndpoint{
			{ID: "e1", Method: "POST", URL: "api/app/order/detail", Tags: []string{business.TagIDOR, business.TagOrder}},
			{ID: "e2", Method: "POST", URL: "api/app/sms/sendVerificationCodeSms", Tags: []string{business.TagSMS, business.TagAuth}},
		},
		Hypotheses: []business.Hypothesis{
			{ID: "BIZ-002", Surface: business.TagIDOR, Title: "IDOR", Severity: "high", Confidence: "medium", Status: "needs_server_validation"},
			{ID: "BIZ-001", Surface: business.TagAuth, Title: "Auth", Severity: "high", Confidence: "medium", Status: "needs_server_validation"},
		},
	}
	if err := business.WriteReport(root, surface); err != nil {
		t.Fatal(err)
	}
	// findings for update
	auditDir := filepath.Join(gwx, "ai_audit")
	_ = os.MkdirAll(auditDir, 0755)
	findings := []map[string]interface{}{
		{"id": "BIZ-002", "status": "needs_server_validation", "title": "IDOR", "severity": "high", "confidence": "medium", "evidence": []interface{}{}},
		{"id": "BIZ-001", "status": "needs_server_validation", "title": "Auth", "severity": "high", "confidence": "medium", "evidence": []interface{}{}},
	}
	fb, _ := json.Marshal(findings)
	_ = os.WriteFile(filepath.Join(auditDir, "findings.json"), fb, 0644)

	// dry-run
	dry, err := Run(Options{
		Dir:            root,
		BaseURL:        srv.URL,
		IAuthorizeLive: true,
		DryRun:         true,
		MaxRequests:    20,
	})
	if err != nil {
		t.Fatalf("dry: %v", err)
	}
	if dry.RequestCount != 0 {
		t.Fatalf("dry-run should not send requests, got %d", dry.RequestCount)
	}

	// live
	live, err := Run(Options{
		Dir:            root,
		BaseURL:        srv.URL,
		IAuthorizeLive: true,
		MaxRequests:    30,
		ProbeIDs:       []string{"1", "2"},
		QPS:            100,
	})
	if err != nil {
		t.Fatalf("live: %v", err)
	}
	if live.RequestCount == 0 {
		t.Fatal("expected live requests")
	}
	// SMS path must be skipped
	smsSkipped := false
	for _, p := range live.Probes {
		if stringsContains(p.Plan.Path, "sendVerificationCodeSms") {
			if p.Skipped {
				smsSkipped = true
			}
		}
	}
	if !smsSkipped {
		t.Fatal("expected SMS path skipped by safety")
	}

	var idorConfirmed bool
	for _, v := range live.HypothesisVerdicts {
		if v.ID == "BIZ-002" && v.Status == StatusConfirmed {
			idorConfirmed = true
		}
	}
	if !idorConfirmed {
		t.Fatalf("expected BIZ-002 confirmed (unauth sensitive data), verdicts=%+v", live.HypothesisVerdicts)
	}
	if _, err := os.Stat(filepath.Join(gwx, "validation_report.json")); err != nil {
		t.Fatal(err)
	}
	// findings updated
	raw, _ := os.ReadFile(filepath.Join(auditDir, "findings.json"))
	var updated []map[string]interface{}
	_ = json.Unmarshal(raw, &updated)
	ok := false
	for _, f := range updated {
		if f["id"] == "BIZ-002" && f["status"] == StatusConfirmed {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("findings not updated: %s", string(raw))
	}
	if hits == 0 {
		t.Fatal("server got no hits")
	}
}

func TestUnauthDeniedNotFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1229,"data":null,"msg":"授权令牌不正确"}`))
	}))
	defer srv.Close()

	root := t.TempDir()
	surface := &business.SurfaceReport{
		SourceDir: root,
		Summary:   map[string]int{"idor": 1},
		Endpoints: []business.TaggedEndpoint{
			{ID: "e1", Method: "POST", URL: "api/app/order/detail", Tags: []string{business.TagIDOR, business.TagOrder}},
		},
		Hypotheses: []business.Hypothesis{
			{ID: "BIZ-002", Surface: business.TagIDOR, Title: "IDOR", Severity: "high", Confidence: "medium", Status: business.StatusNeedsServer},
			{ID: "BIZ-006", Surface: business.TagWebView, Title: "WV", Severity: "high", Confidence: "high", Status: business.StatusConfirmedStatic, ValidationLayer: "static"},
		},
	}
	if err := business.WriteReport(root, surface); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(root, ".gwxapkg", "ai_audit"), 0755)
	findings := []map[string]interface{}{
		{"id": "BIZ-002", "status": business.StatusNeedsServer, "title": "IDOR", "evidence": []interface{}{}},
		{"id": "BIZ-006", "status": business.StatusConfirmedStatic, "title": "WV", "evidence": []interface{}{}},
	}
	fb, _ := json.Marshal(findings)
	_ = os.WriteFile(filepath.Join(root, ".gwxapkg", "ai_audit", "findings.json"), fb, 0644)

	live, err := Run(Options{
		Dir:            root,
		BaseURL:        srv.URL,
		IAuthorizeLive: true,
		MaxRequests:    20,
		QPS:            100,
		ProbeIDs:       []string{"1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var idor, wv string
	for _, v := range live.HypothesisVerdicts {
		if v.ID == "BIZ-002" {
			idor = v.Status
		}
		if v.ID == "BIZ-006" {
			wv = v.Status
		}
	}
	if idor != StatusAuthIDORUntested && idor != StatusUnauthDenied {
		t.Fatalf("IDOR status=%s want auth_idor_untested or unauth_denied", idor)
	}
	if idor == StatusFalsePositive {
		t.Fatal("IDOR must not be false_positive when only unauth denied")
	}
	if wv != StatusConfirmedStatic {
		t.Fatalf("webview must stay confirmed_static, got %s", wv)
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
