package restore

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/25smoking/Gwxapkg/internal/enum"

	"github.com/25smoking/Gwxapkg/internal/config"
	"github.com/25smoking/Gwxapkg/internal/unpack"
)

// fixSubpackageDir 修正子包目录
func fixSubpackageDir(wxapkg *config.WxapkgInfo, outputDir string) string {
	var e struct {
		SubPackages []unpack.SubPackage `json:"subPackages"`
	}
	content, _ := os.ReadFile(filepath.Join(outputDir, enum.App_Config))
	_ = json.Unmarshal(content, &e)

	// 包内文件名在解包阶段已被规范为相对路径；旧实现却把分包 root
	// 强制改成了以 / 开头的路径，导致匹配永远失败。随后 SourcePath 变成
	// 空字符串，解析器便会以进程当前工作目录写入文件。
	sourcePath := normalizePackageRelativePath(wxapkg.SourcePath)
	for _, subPackage := range e.SubPackages {
		root := normalizePackageRelativePath(subPackage.Root)
		if root == "" {
			continue
		}
		if isPathInSubpackage(sourcePath, root) || hasFileInSubpackage(wxapkg.RawFiles, root) {
			return filepath.Join(outputDir, filepath.FromSlash(root))
		}
	}

	// 即使包元数据异常，也绝不返回空目录，避免任何解析器退回到当前工作目录。
	// 有目录信息时仍可在输出目录内做保守恢复。
	if dir := pathDirWithinOutput(sourcePath); dir != "" {
		return filepath.Join(outputDir, filepath.FromSlash(dir))
	}
	return outputDir
}

func normalizePackageRelativePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.Trim(value, "/")
	if value == "" {
		return ""
	}
	value = path.Clean(value)
	if value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return ""
	}
	return strings.TrimPrefix(value, "./")
}

func isPathInSubpackage(filePath, root string) bool {
	return filePath == root || strings.HasPrefix(filePath, root+"/")
}

func hasFileInSubpackage(files []string, root string) bool {
	for _, file := range files {
		if isPathInSubpackage(normalizePackageRelativePath(file), root) {
			return true
		}
	}
	return false
}

func pathDirWithinOutput(filePath string) string {
	dir := filepath.ToSlash(filepath.Dir(filepath.FromSlash(filePath)))
	if dir == "." || dir == "/" || strings.HasPrefix(dir, "../") {
		return ""
	}
	return strings.Trim(dir, "/")
}

// ProjectStructure 是否还原工程目录结构
func ProjectStructure(outputDir string, restoreDir bool) {
	if !restoreDir {
		return
	}

	configManager := config.NewSharedConfigManager()

	// 创建文件删除管理器
	manager := config.NewFileDeletionManager()

	defer func() {
		if noClean, ok := configManager.Get("noClean"); ok {
			if !noClean.(bool) {
				// 执行删除文件操作
				manager.DeleteFiles()
			}
		}
	}()

	// 包管理器
	wxakpgManager := config.GetWxapkgManager()

	// 修正子包目录
	for _, wxapkg := range wxakpgManager.Packages {
		if IsSubpackage(wxapkg) {
			wxapkg.SourcePath = fixSubpackageDir(wxapkg, outputDir)
		}
	}

	// 反编译
	decompiler := new(WxapkgDecompiler)
	// 执行反编译操作
	decompiler.Decompile(outputDir)

	// 创建命令执行器, 执行解析器
	executor := NewCommandExecutor(wxakpgManager)
	executor.ExecuteAll()
}
