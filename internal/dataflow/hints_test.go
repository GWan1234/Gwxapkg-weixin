package dataflow

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeFindsStorageAndCryptoHints(t *testing.T) {
	root := t.TempDir()
	js := `
function load() {
  const token = wx.getStorageSync('token');
  wx.request({ url: '/api/me', header: { Authorization: token } });
}
function login(data) {
  const body = CryptoJS.AES.encrypt(JSON.stringify(data), key).toString();
  wx.request({ url: '/api/login', data: body });
}
`
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(js), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeAndWrite(root)
	if err != nil {
		t.Fatalf("AnalyzeAndWrite: %v", err)
	}
	if report.HintCount == 0 {
		t.Fatal("expected hints")
	}
	if _, err := os.Stat(filepath.Join(root, ".gwxapkg", "dataflow_hints.json")); err != nil {
		t.Fatalf("missing output: %v", err)
	}
}
