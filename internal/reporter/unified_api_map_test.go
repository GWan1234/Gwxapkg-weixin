package reporter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/scanner"
	"github.com/25smoking/Gwxapkg/internal/semantic"
)

func TestGenerateUnifiedAPIMapMergesSources(t *testing.T) {
	root := t.TempDir()

	scanReport := &scanner.ScanReport{
		AppID: "wx_demo",
		APIEndpoints: []scanner.APIEndpoint{
			{
				Name:       "POST /api/login",
				Method:     "POST",
				RawURL:     "/api/login",
				FilePath:   "pages/login.js",
				LineNumber: 12,
				SourceRule: "object-request",
				Context:    `wx.request({url:"/api/login",method:"POST"})`,
			},
			{
				Name:       "GET /api/only-http",
				Method:     "GET",
				RawURL:     "/api/only-http",
				FilePath:   "pages/a.js",
				LineNumber: 3,
				SourceRule: "url-field",
			},
		},
	}

	semanticReport := &semantic.APIMapReport{
		Endpoints: []semantic.APIEndpointEntry{
			{
				FunctionName:   "login",
				ControllerName: "user",
				MethodsName:    "login",
				HTTPMethod:     "POST",
				URL:            "/api/login",
				FilePath:       "api/user.js",
			},
			{
				FunctionName:   "profile",
				ControllerName: "user",
				MethodsName:    "profile",
				HTTPMethod:     "GET",
				FilePath:       "api/user.js",
			},
		},
	}

	artifacts, err := GenerateUnifiedAPIMap(root, root, scanReport, semanticReport)
	if err != nil {
		t.Fatalf("GenerateUnifiedAPIMap: %v", err)
	}
	if artifacts == nil {
		t.Fatal("expected artifacts")
	}
	if artifacts.MergedCount != 1 {
		t.Fatalf("merged=%d want 1", artifacts.MergedCount)
	}
	if artifacts.EndpointCount < 3 {
		t.Fatalf("endpoint count=%d want >=3", artifacts.EndpointCount)
	}

	data, err := os.ReadFile(filepath.Join(root, ".gwxapkg", "api_unified_map.json"))
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty unified map")
	}
	md, err := os.ReadFile(filepath.Join(root, ".gwxapkg", "api_unified_map.md"))
	if err != nil {
		t.Fatalf("read md: %v", err)
	}
	if len(md) == 0 {
		t.Fatal("empty markdown")
	}
}

func TestGenerateUnifiedAPIMapHTTPOnly(t *testing.T) {
	root := t.TempDir()
	scanReport := &scanner.ScanReport{
		APIEndpoints: []scanner.APIEndpoint{
			{Method: "GET", RawURL: "/api/x", FilePath: "a.js", SourceRule: "fetch"},
		},
	}
	artifacts, err := GenerateUnifiedAPIMap(root, root, scanReport, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if artifacts == nil || artifacts.EndpointCount != 1 {
		t.Fatalf("artifacts=%+v", artifacts)
	}
}
