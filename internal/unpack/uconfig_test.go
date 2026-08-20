package unpack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/config"
)

func TestConfigParserSupportsMissingEntryPageAndPreservesSubpackagePages(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "app-config.json")
	rawConfig := []byte(`{
  "pages": ["pages/home/index.html", "pkg/detail/index.html"],
  "global": {
    "window": {"navigationBarTitleText": "demo"},
    "usingComponents": {"x-card": "/components/card/index"}
  },
  "tabBar": {
    "list": [{"pagePath": "pages/home/index.html", "iconPath": "assets/home.png"}]
  },
  "subPackages": [{
    "root": "pkg",
    "pages": ["detail/index.html"],
    "independent": true
  }],
  "page": {}
}`)
	if err := os.WriteFile(configPath, rawConfig, 0644); err != nil {
		t.Fatal(err)
	}

	parser := &ConfigParser{}
	err := parser.Parse(config.WxapkgInfo{Option: &config.WxapkgOption{AppConfigSource: configPath}})
	if err != nil {
		t.Fatalf("配置还原失败: %v", err)
	}

	appJSON, err := os.ReadFile(filepath.Join(dir, "app.json"))
	if err != nil {
		t.Fatalf("应生成 app.json: %v", err)
	}
	var app AppConfig
	if err := json.Unmarshal(appJSON, &app); err != nil {
		t.Fatalf("解析 app.json 失败: %v", err)
	}

	if !reflect.DeepEqual(app.Pages, []string{"pages/home/index"}) {
		t.Fatalf("主包页面还原错误: %#v", app.Pages)
	}
	if app.Window["navigationBarTitleText"] != "demo" {
		t.Fatalf("应从 global.window 还原窗口配置: %#v", app.Window)
	}
	if app.UsingComponents["x-card"] != "/components/card/index" {
		t.Fatalf("应从 global.usingComponents 还原全局组件: %#v", app.UsingComponents)
	}
	if len(app.SubPackages) != 1 || !app.SubPackages[0].Independent || !reflect.DeepEqual(app.SubPackages[0].Pages, []string{"detail/index"}) {
		t.Fatalf("分包配置还原错误: %#v", app.SubPackages)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("原始 app-config.json 不应丢失: %v", err)
	}
	if !reflect.DeepEqual(after, rawConfig) {
		t.Fatal("原始 app-config.json 不应被改写")
	}
}

func TestConfigParserPrependsEntryPageWhenItIsNotDeclared(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "app-config.json")
	if err := os.WriteFile(configPath, []byte(`{
  "pages": ["pages/second/index"],
  "entryPagePath": "pages/first/index.html",
  "global": {},
  "page": {}
}`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := (&ConfigParser{}).Parse(config.WxapkgInfo{Option: &config.WxapkgOption{AppConfigSource: configPath}}); err != nil {
		t.Fatalf("配置还原失败: %v", err)
	}
	appJSON, err := os.ReadFile(filepath.Join(dir, "app.json"))
	if err != nil {
		t.Fatal(err)
	}
	var app AppConfig
	if err := json.Unmarshal(appJSON, &app); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(app.Pages, []string{"pages/first/index", "pages/second/index"}) {
		t.Fatalf("首页排序错误: %#v", app.Pages)
	}
}

func TestConfigParserNeverWritesComponentsOutsideOutputDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "result")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "app-config.json")
	if err := os.WriteFile(configPath, []byte(`{
  "pages": ["pages/feature/index.html"],
  "page": {
    "pages/feature/index.html": {
      "window": {"usingComponents": {"card": "../../components/card/index"}}
    },
    "../escape/index.html": {"window": {"component": true}}
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := (&ConfigParser{}).Parse(config.WxapkgInfo{Option: &config.WxapkgOption{AppConfigSource: configPath}}); err != nil {
		t.Fatalf("配置还原失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "components", "card", "index.json")); err != nil {
		t.Fatalf("合法组件配置应写入输出目录: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape", "index.json")); !os.IsNotExist(err) {
		t.Fatalf("越界页面配置不应写入输出目录上级: %v", err)
	}
}
