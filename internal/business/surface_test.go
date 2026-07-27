package business

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/reporter"
	"github.com/25smoking/Gwxapkg/internal/scanner"
)

func TestAnalyzeBusinessSurfaces(t *testing.T) {
	root := t.TempDir()

	// unified map with auth + order + pay endpoints
	scan := &scanner.ScanReport{
		AppID: "wx_demo",
		APIEndpoints: []scanner.APIEndpoint{
			{Method: "POST", RawURL: "/api/user/login", FilePath: "api/auth.js", LineNumber: 10, SourceRule: "object-request"},
			{Method: "POST", RawURL: "/api/sms/sendCode", FilePath: "api/auth.js", LineNumber: 20, SourceRule: "object-request"},
			{Method: "GET", RawURL: "/api/order/detail?orderId=1", FilePath: "api/order.js", LineNumber: 5, SourceRule: "url-field"},
			{Method: "POST", RawURL: "/api/pay/prepay", FilePath: "api/pay.js", LineNumber: 8, SourceRule: "object-request"},
			{Method: "POST", RawURL: "/api/file/upload", FilePath: "api/upload.js", LineNumber: 3, SourceRule: "object-request"},
		},
	}
	if _, err := reporter.GenerateUnifiedAPIMap(root, root, scan, nil); err != nil {
		t.Fatalf("unified map: %v", err)
	}

	// route manifest pages
	routes := map[string]interface{}{
		"pages": []map[string]interface{}{
			{"route": "pages/login/index", "title": "登录", "files": map[string]string{"js": "pages/login/index.js", "wxml": "pages/login/index.wxml"}},
			{"route": "pages/order/detail", "title": "订单详情", "files": map[string]string{"js": "pages/order/detail.js"}},
			{"route": "pages/pay/checkout", "title": "收银台", "files": map[string]string{"js": "pages/pay/checkout.js"}},
		},
	}
	rb, _ := json.Marshal(routes)
	if err := os.WriteFile(filepath.Join(root, "route_manifest.json"), rb, 0644); err != nil {
		t.Fatal(err)
	}

	// code signals
	if err := os.MkdirAll(filepath.Join(root, "pages/login"), 0755); err != nil {
		t.Fatal(err)
	}
	js := `
Page({
  onLoad() {
    const token = wx.getStorageSync('token');
    wx.login({ success() {} });
  },
  onShareAppMessage() { return { title: 'x' } }
})
`
	if err := os.WriteFile(filepath.Join(root, "pages/login/index.js"), []byte(js), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pages/login/index.wxml"), []byte(`<web-view src="{{url}}"></web-view>`), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeAndWrite(root)
	if err != nil {
		t.Fatalf("AnalyzeAndWrite: %v", err)
	}
	if len(report.Endpoints) < 4 {
		t.Fatalf("tagged endpoints=%d want >=4", len(report.Endpoints))
	}
	if len(report.Hypotheses) < 3 {
		t.Fatalf("hypotheses=%d want >=3", len(report.Hypotheses))
	}
	if report.Summary[TagAuth] == 0 && report.Summary["page_"+TagAuth] == 0 {
		t.Fatal("expected auth surface")
	}
	if report.Summary[TagPayment] == 0 {
		t.Fatal("expected payment surface")
	}
	if _, err := os.Stat(filepath.Join(root, ".gwxapkg", "business_surface.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".gwxapkg", "business_surface.md")); err != nil {
		t.Fatal(err)
	}

	// unified map should be annotated
	data, err := os.ReadFile(filepath.Join(root, ".gwxapkg", "api_unified_map.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(data), "business_tags") {
		t.Fatal("expected business_tags in unified map")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && (func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})()))
}
