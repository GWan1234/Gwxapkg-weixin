package restore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/config"
	"github.com/25smoking/Gwxapkg/internal/enum"
)

func TestSetAppPreservesOriginalRuntimeArtifacts(t *testing.T) {
	dir := t.TempDir()
	artifacts := []string{
		"app-config.json",
		"app-service.js",
		"app-wxss.js",
		"appservice.app.js",
		"common.app.js",
	}
	for _, name := range artifacts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	setApp(&config.WxapkgInfo{
		WxapkgType:  enum.App_V3,
		SourcePath:  dir,
		IsExtracted: true,
		Option:      &config.WxapkgOption{SetAppConfig: true},
	})
	config.NewFileDeletionManager().DeleteFiles()

	for _, name := range artifacts {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("原始运行时文件 %s 不应被默认清理: %v", name, err)
		}
	}
}

func TestFixSubpackageDirStaysInsideOutputDir(t *testing.T) {
	outputDir := t.TempDir()
	configJSON := []byte(`{"subPackages":[{"root":"supermarket/"},{"root":"__plugin__/"}]}`)
	if err := os.WriteFile(filepath.Join(outputDir, "app-config.json"), configJSON, 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("相对路径分包", func(t *testing.T) {
		got := fixSubpackageDir(&config.WxapkgInfo{
			SourcePath: "supermarket/page-frame.js",
			RawFiles:   []string{"page-frame.js", "supermarket/pages/index.js"},
		}, outputDir)
		want := filepath.Join(outputDir, "supermarket")
		if got != want {
			t.Fatalf("分包目录错误: got %q, want %q", got, want)
		}
	})

	t.Run("无法识别时不回退工作目录", func(t *testing.T) {
		got := fixSubpackageDir(&config.WxapkgInfo{SourcePath: "page-frame.js"}, outputDir)
		if got != outputDir {
			t.Fatalf("异常分包必须回退至输出目录: got %q, want %q", got, outputDir)
		}
	})
}
