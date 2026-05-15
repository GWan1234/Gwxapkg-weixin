package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/cmd"
	internalcmd "github.com/25smoking/Gwxapkg/internal/cmd"
	"github.com/25smoking/Gwxapkg/internal/locator"
	"github.com/25smoking/Gwxapkg/internal/pack"
	"github.com/25smoking/Gwxapkg/internal/packagecheck"
	"github.com/25smoking/Gwxapkg/internal/semantic"
	"github.com/25smoking/Gwxapkg/internal/ui"
	"github.com/25smoking/Gwxapkg/internal/util"
)

func main() {
	// 检查是否有子命令
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "all":
			handleAllCommand(os.Args[2:])
			return
		case "scan":
			handleScanCommand(os.Args[2:])
			return
		case "scan-only":
			handleScanOnlyCommand(os.Args[2:])
			return
		case "semantic":
			handleSemanticCommand(os.Args[2:])
			return
		case "api-link":
			handleAPILinkCommand(os.Args[2:])
			return
		case "repack":
			handleRepackCommand(os.Args[2:])
			return
		}
	}

	// 默认命令行模式
	handleDefaultCommand()
}

// handleAllCommand 处理 all 子命令：自动扫描并处理指定 AppID 的所有文件
// 支持以下方式指定 AppID：
//   - -id=wx111            单个
//   - -id=wx111,wx222      逗号分隔
//   - -id-file=ids.txt     每行一个的文件
//   - --all                处理所有已缓存的小程序
func handleAllCommand(args []string) {
	allFlags := flag.NewFlagSet("all", flag.ExitOnError)
	appID := allFlags.String("id", "", "微信小程序的AppID，支持逗号分隔多个")
	appIDFile := allFlags.String("id-file", "", "AppID 列表文件路径（每行一个）")
	allApps := allFlags.Bool("all", false, "处理所有已缓存的小程序")
	verbose := allFlags.Bool("verbose", false, "显示扫描候选路径诊断")
	outputDir := allFlags.String("out", "", "输出目录路径")
	restoreDir := allFlags.Bool("restore", true, "是否还原工程目录结构")
	pretty := allFlags.Bool("pretty", true, "是否美化输出")
	noClean := allFlags.Bool("noClean", false, "是否保留中间文件")
	save := allFlags.Bool("save", false, "是否保存解密后的文件")
	sensitive := allFlags.Bool("sensitive", true, "是否获取敏感数据")
	postman := allFlags.Bool("postman", false, "是否导出 Postman Collection")
	workspace := allFlags.Bool("workspace", false, "是否保留可精确回包的工作区")
	watch := allFlags.Bool("watch", false, "只监听缺失分包下载，不执行解包")
	astRename := allFlags.String("ast-rename", semantic.ASTRenameModeDeep, "AST 重命名模式: off/report/safe/deep")
	astDiff := allFlags.Bool("ast-diff", true, "是否生成 AST 重命名 diff 报告")
	astPatch := allFlags.Bool("ast-patch", true, "是否生成 AST 重命名 patch")

	allFlags.Parse(args)

	ui.Banner()

	// 收集 AppID 列表
	var appIDs []string
	var programs []locator.MiniProgramInfo

	if *allApps {
		// --all 模式：扫描所有已缓存小程序
		ui.Info("正在扫描所有已缓存的小程序...")
		ui.Info("名称优先从包内元数据提取；模板类运行时名称补查失败时将留空")
		var err error
		programs, err = scanPrograms(*verbose)
		if err != nil {
			ui.Error("扫描失败: %v", err)
			return
		}
		for _, p := range programs {
			appIDs = append(appIDs, p.AppID)
		}
	} else if *appIDFile != "" {
		// 从文件读取 AppID
		data, err := os.ReadFile(*appIDFile)
		if err != nil {
			ui.Error("读取 AppID 文件失败: %v", err)
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				appIDs = append(appIDs, line)
			}
		}
	} else if *appID != "" {
		// 逗号分隔或单个 AppID
		for _, id := range strings.Split(*appID, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				appIDs = append(appIDs, id)
			}
		}
	}

	if len(appIDs) == 0 {
		ui.Error("请指定 AppID: ./Gwxapkg all -id=<AppID>")
		ui.Info("或使用 -id-file=ids.txt 指定文件，或 --all 处理全部")
		return
	}
	if *watch && len(appIDs) > 1 {
		ui.Error("-watch 只支持单个 AppID，请使用 all -id=<AppID> -watch")
		return
	}

	ui.Info("准备处理 %d 个小程序", len(appIDs))
	fmt.Println()

	// 扫描已缓存的小程序
	if programs == nil {
		var err error
		programs, err = scanPrograms(*verbose)
		if err != nil {
			ui.Error("扫描失败: %v", err)
			return
		}
	}

	// 建立 AppID -> MiniProgramInfo 映射
	programMap := make(map[string]*locator.MiniProgramInfo)
	for i := range programs {
		programMap[programs[i].AppID] = &programs[i]
	}

	// 逐个处理
	for i, id := range appIDs {
		if len(appIDs) > 1 {
			ui.PrintDivider()
			ui.Step(i+1, len(appIDs), "处理: %s", id)
		}

		matched, ok := programMap[id]
		if !ok {
			ui.Error("未找到 AppID: %s，跳过", id)
			continue
		}

		displayName := matched.AppID
		if matched.AppName != "" {
			displayName = matched.AppName + " (" + matched.AppID + ")"
		}
		ui.Success("找到小程序: %s （版本 %s, %d 个文件）", displayName, matched.Version, len(matched.Files))

		resolvedOutputDir := *outputDir
		if resolvedOutputDir == "" {
			resolvedOutputDir = internalcmd.DetermineOutputDir(matched.Path, id)
		}
		if *watch {
			ui.Info("watch 模式只监听分包下载，不执行解包；需要合并源码时请退出后运行普通 scan 或 all")
			report := buildWatchReport(id, matched.Path, resolvedOutputDir)
			watchPackageDownloads(id, matched.Path, resolvedOutputDir, report)
			continue
		}

		rewriteOptions := buildRewriteOptions(*astRename, *astDiff, *astPatch)
		cmd.ExecuteWithOptions(id, matched.Path, resolvedOutputDir, ".wxapkg", *restoreDir, *pretty, *noClean, *save, *sensitive, *postman, *workspace, rewriteOptions)
	}

	ui.PrintDivider()
	ui.Success("全部处理完成! (%d 个小程序)", len(appIDs))
}

// handleScanCommand 处理 scan 子命令（交互式选择解包）
func handleScanCommand(args []string) {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
	verbose := scanFlags.Bool("verbose", false, "显示扫描候选路径诊断")
	postman := scanFlags.Bool("postman", false, "是否导出 Postman Collection")
	watch := scanFlags.Bool("watch", false, "只监听缺失分包下载，不执行解包")
	astRename := scanFlags.String("ast-rename", semantic.ASTRenameModeDeep, "AST 重命名模式: off/report/safe/deep")
	astDiff := scanFlags.Bool("ast-diff", true, "是否生成 AST 重命名 diff 报告")
	astPatch := scanFlags.Bool("ast-patch", true, "是否生成 AST 重命名 patch")
	scanFlags.Parse(args)

	ui.Banner()
	ui.Info("正在扫描微信小程序目录...")
	ui.Info("名称优先从包内元数据提取；模板类运行时名称补查失败时将留空")
	fmt.Println()

	programs, err := scanPrograms(*verbose)
	if err != nil {
		ui.Error("扫描失败: %v", err)
		return
	}

	if len(programs) == 0 {
		ui.Warning("未找到任何微信小程序缓存")
		return
	}

	ui.Success("找到 %d 个小程序", len(programs))
	ui.PrintDivider()
	fmt.Println()

	for i, p := range programs {
		ui.PrintMiniProgramWithName(i+1, p.AppID, p.AppName, p.Version, p.UpdateTime, len(p.Files), p.Path)
	}

	ui.PrintDivider()

	// 交互式选择
	choice := ui.Prompt(len(programs))
	if choice == -1 {
		ui.Info("已退出")
		return
	}

	selected := programs[choice-1]
	displayName := selected.AppID
	if selected.AppName != "" {
		displayName = selected.AppName + " (" + selected.AppID + ")"
	}
	ui.Success("已选择: %s", displayName)
	fmt.Println()

	outputDir := internalcmd.DetermineOutputDir(selected.Path, selected.AppID)
	if *watch {
		ui.Info("完整性报告读取目录: %s", outputDir)
	} else {
		ui.Info("解包结果将保存到: %s", outputDir)
	}
	fmt.Println()

	if *watch {
		ui.Info("watch 模式只监听分包下载，不执行解包；需要合并源码时请退出后运行普通 scan 或 all")
		report := buildWatchReport(selected.AppID, selected.Path, outputDir)
		watchPackageDownloads(selected.AppID, selected.Path, outputDir, report)
		ui.PrintDivider()
		ui.Success("watch 已结束")
		return
	}

	// 直接进入解包流程（复用 all 命令的默认参数）
	rewriteOptions := buildRewriteOptions(*astRename, *astDiff, *astPatch)
	cmd.ExecuteWithOptions(selected.AppID, selected.Path, outputDir, ".wxapkg", true, true, false, false, true, *postman, false, rewriteOptions)

	ui.PrintDivider()
	ui.Success("处理完成!")
}

func buildWatchReport(appID, inputDir, outputDir string) *packagecheck.Report {
	report, err := packagecheck.Analyze(outputDir, appID, mapKeys(snapshotWxapkgFiles(inputDir)))
	if err == nil && report != nil && report.Status != packagecheck.StatusUnknown {
		return report
	}
	existing, readErr := packagecheck.ReadReport(outputDir)
	if readErr == nil {
		return existing
	}
	return nil
}

func watchPackageDownloads(appID, inputDir, outputDir string, report *packagecheck.Report) {
	if report.IsFull() {
		ui.Success("分包已完整，无需进入 watch")
		return
	}

	ui.Warning("进入缺失分包监控模式: %s", appID)
	ui.Info("   - 请在微信中打开缺失功能页，客户端下载新分包后工具会自动捕获")
	ui.Info("   - 监听目录: %s", inputDir)
	if report == nil || report.Status == packagecheck.StatusUnknown {
		ui.Warning("   - 未找到可用的完整性报告，当前仅提示新增 wxapkg；先运行普通 scan 可生成缺失清单")
	} else {
		printWatchMissingRoots(report)
	}

	known := snapshotWxapkgFiles(inputDir)
	ui.Info("   - 当前已缓存 wxapkg: %d", len(known))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-sigCh:
			ui.Info("已退出 watch；需要合并新分包时请运行普通 scan 或 all -id=%s", appID)
			ui.Info("当前输出目录: %s", outputDir)
			return
		case <-ticker.C:
			current := snapshotWxapkgFiles(inputDir)
			newFiles := diffFileSet(known, current)
			if len(newFiles) == 0 {
				continue
			}
			sort.Strings(newFiles)
			for _, file := range newFiles {
				ui.Success("捕获新 wxapkg: %s", file)
			}
			known = current
			report = buildWatchReport(appID, inputDir, outputDir)
			printWatchProgress(report, len(known))
		}
	}
}

func printWatchProgress(report *packagecheck.Report, cachedPackageCount int) {
	ui.Info("   - 当前已缓存 wxapkg: %d", cachedPackageCount)
	if report == nil || report.Status == packagecheck.StatusUnknown {
		return
	}
	if report.IsFull() {
		ui.Success("分包包文件已补齐；退出 watch 后运行普通 scan/all 重新解包即可合并源码")
		return
	}
	printWatchMissingRoots(report)
}

func printWatchMissingRoots(report *packagecheck.Report) {
	if report == nil || len(report.MissingSubpackages) == 0 {
		return
	}
	ui.Info("   - 仍缺失分包: %d", len(report.MissingSubpackages))
	limit := len(report.MissingSubpackages)
	if limit > 10 {
		limit = 10
	}
	for _, root := range report.MissingSubpackages[:limit] {
		ui.Info("     · %s", root)
	}
	if len(report.MissingSubpackages) > limit {
		ui.Info("     · ... 还有 %d 个", len(report.MissingSubpackages)-limit)
	}
}

func snapshotWxapkgFiles(dir string) map[string]struct{} {
	result := make(map[string]struct{})
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".wxapkg") {
			result[filepath.Clean(path)] = struct{}{}
		}
		return nil
	})
	return result
}

func diffFileSet(previous, current map[string]struct{}) []string {
	result := make([]string, 0)
	for file := range current {
		if _, ok := previous[file]; !ok {
			result = append(result, file)
		}
	}
	return result
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func scanPrograms(verbose bool) ([]locator.MiniProgramInfo, error) {
	report, err := locator.ScanWithOptions(locator.ScanOptions{Verbose: verbose})
	if err != nil {
		return nil, err
	}

	if verbose {
		printScanDiagnostics(report.Diagnostics)
	}

	return report.Programs, nil
}

func printScanDiagnostics(diagnostics []locator.ScanDiagnostic) {
	for _, diagnostic := range diagnostics {
		message := formatScanDiagnostic(diagnostic)
		switch diagnostic.Status {
		case "missing", "no-access", "stat-error", "glob-error", "scan-error", "config-error", "unsupported":
			ui.Warning(message)
		default:
			ui.Info(message)
		}
	}

	if len(diagnostics) > 0 {
		fmt.Println()
	}
}

func formatScanDiagnostic(diagnostic locator.ScanDiagnostic) string {
	if diagnostic.Path == "" {
		return fmt.Sprintf("[%s] %s", diagnostic.Status, diagnostic.Detail)
	}
	if diagnostic.Detail == "" {
		return fmt.Sprintf("[%s] %s", diagnostic.Status, diagnostic.Path)
	}
	return fmt.Sprintf("[%s] %s -> %s", diagnostic.Status, diagnostic.Path, diagnostic.Detail)
}

// handleScanOnlyCommand 处理 scan-only 子命令
func handleScanOnlyCommand(args []string) {
	f := flag.NewFlagSet("scan-only", flag.ExitOnError)
	dir := f.String("dir", "", "已解包的目录路径")
	appID := f.String("id", "", "AppID（可选，用于报告标题）")
	format := f.String("format", "both", "报告格式: json / excel / html / both")
	out := f.String("out", "", "报告输出目录（默认与 -dir 相同）")
	postman := f.Bool("postman", false, "是否导出 Postman Collection")
	f.Parse(args)

	ui.Banner()

	// 支持位置参数
	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("请指定目录: ./Gwxapkg scan-only -dir=<已解包目录>")
		return
	}

	internalcmd.ScanOnly(*dir, *appID, *format, *out, *postman)
}

func handleSemanticCommand(args []string) {
	f := flag.NewFlagSet("semantic", flag.ExitOnError)
	dir := f.String("dir", "", "已解包目录路径")
	astRename := f.String("ast-rename", semantic.ASTRenameModeDeep, "AST 重命名模式: off/report/safe/deep")
	astDiff := f.Bool("ast-diff", true, "是否生成 AST 重命名 diff 报告")
	astPatch := f.Bool("ast-patch", true, "是否生成 AST 重命名 patch")
	astRollback := f.Bool("ast-rollback", false, "是否回滚 AST 重命名写回")
	f.Parse(args)

	ui.Banner()

	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("请指定目录: ./Gwxapkg semantic -dir=<已解包目录>")
		return
	}

	expandedDir, err := util.ExpandHomePath(*dir)
	if err != nil {
		ui.Warning("展开目录失败，继续使用原路径: %v", err)
		expandedDir = *dir
	}
	info, err := os.Stat(expandedDir)
	if err != nil {
		ui.Error("目录不可访问: %v", err)
		return
	}
	if !info.IsDir() {
		ui.Error("semantic 需要传入已解包目录")
		return
	}

	if *astRollback {
		report, err := semantic.RollbackASTRenames(expandedDir)
		if err != nil {
			ui.Error("AST 重命名回滚失败: %v", err)
			return
		}
		ui.Success("AST 重命名已回滚: %d 个文件", len(report.RestoredFiles))
		return
	}

	rewriteOptions := buildRewriteOptions(*astRename, *astDiff, *astPatch)
	printASTRenameNotice(rewriteOptions.ASTRename)
	report, err := semantic.RewriteProjectWithOptions(expandedDir, rewriteOptions)
	if err != nil {
		ui.Error("源码语义反混淆失败: %v", err)
		return
	}

	ui.Success("源码语义映射: %s", filepath.Join(expandedDir, ".gwxapkg", "semantic_module_map.json"))
	ui.Info("   - 语义重命名: %d | require 重写: %d | SourceMap 源码: %d",
		report.RenamedCount,
		report.RewrittenRequireCount,
		report.SourceMapRecovered,
	)
	if report.APIEndpointCount > 0 {
		ui.Success("API 地图: %s", filepath.Join(expandedDir, ".gwxapkg", "api_map.md"))
		ui.Info("   - API 函数: %d | 细拆模块: %d",
			report.APIEndpointCount,
			report.APISplitCount,
		)
		ui.Success("API 调用链: %s", filepath.Join(expandedDir, ".gwxapkg", "api_call_chain.md"))
		ui.Success("API 伪代码: %s", filepath.Join(expandedDir, ".gwxapkg", "api_pseudo.md"))
	}
	if report.ASTRenamedCount > 0 {
		ui.Success("AST 重命名报告: %s", filepath.Join(expandedDir, ".gwxapkg", "ast_rename_map.json"))
		ui.Info("   - AST 重命名: %d | 文件数: %d",
			report.ASTRenamedCount,
			report.ASTRenamedFiles,
		)
	}
}

func handleAPILinkCommand(args []string) {
	f := flag.NewFlagSet("api-link", flag.ExitOnError)
	dir := f.String("dir", "", "已解包目录路径")
	burpFile := f.String("burp-file", "", "Burp 原始请求文件")
	f.Parse(args)

	ui.Banner()

	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("请指定目录: ./Gwxapkg api-link -dir=<已解包目录> -burp-file=<raw_request.txt>")
		return
	}

	expandedDir, err := util.ExpandHomePath(*dir)
	if err != nil {
		ui.Warning("展开目录失败，继续使用原路径: %v", err)
		expandedDir = *dir
	}

	var raw []byte
	if *burpFile != "" {
		expandedFile, err := util.ExpandHomePath(*burpFile)
		if err != nil {
			ui.Warning("展开 Burp 文件失败，继续使用原路径: %v", err)
			expandedFile = *burpFile
		}
		raw, err = os.ReadFile(expandedFile)
		if err != nil {
			ui.Error("读取 Burp 请求失败: %v", err)
			return
		}
	} else {
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			ui.Error("读取 stdin 失败: %v", err)
			return
		}
	}
	if strings.TrimSpace(string(raw)) == "" {
		ui.Error("Burp 原始请求为空")
		return
	}

	report, err := semantic.LinkBurpRequest(expandedDir, string(raw))
	if err != nil {
		ui.Error("Burp 请求关联失败: %v", err)
		return
	}
	ui.Success("Burp API 关联报告: %s", filepath.Join(expandedDir, ".gwxapkg", "burp_api_link.md"))
	ui.Info("   - 匹配候选: %d", len(report.Matches))
}

func handleRepackCommand(args []string) {
	repackFlags := flag.NewFlagSet("repack", flag.ExitOnError)
	inputDir := repackFlags.String("in", "", "输入目录路径")
	outputDir := repackFlags.String("out", "", "输出目录路径")
	watch := repackFlags.Bool("watch", false, "是否监听文件夹")
	appID := repackFlags.String("id", "", "小程序 AppID（用于生成微信可直接打开的加密包）")
	raw := repackFlags.Bool("raw", false, "输出未加密 wxapkg（仅供测试）")

	repackFlags.Parse(args)

	ui.Banner()

	if *inputDir == "" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		*inputDir = args[0]
	}

	if *inputDir == "" {
		ui.Error("请指定输入目录: ./Gwxapkg repack -in=<目录>")
		return
	}

	ui.Info("重新打包模式")
	pack.Repack(*inputDir, *watch, *outputDir, *appID, *raw)
}

// handleDefaultCommand 处理默认命令行模式
func handleDefaultCommand() {
	appID := flag.String("id", "", "微信小程序的AppID")
	input := flag.String("in", "", "输入文件路径")
	outputDir := flag.String("out", "", "输出目录路径")
	fileExt := flag.String("ext", ".wxapkg", "处理的文件后缀")
	restoreDir := flag.Bool("restore", true, "是否还原工程目录结构")
	pretty := flag.Bool("pretty", true, "是否美化输出")
	noClean := flag.Bool("noClean", false, "是否保留中间文件")
	save := flag.Bool("save", false, "是否保存解密后的文件")
	sensitive := flag.Bool("sensitive", true, "是否获取敏感数据")
	postman := flag.Bool("postman", false, "是否导出 Postman Collection")
	workspace := flag.Bool("workspace", false, "是否保留可精确回包的工作区")
	astRename := flag.String("ast-rename", semantic.ASTRenameModeDeep, "AST 重命名模式: off/report/safe/deep")
	astDiff := flag.Bool("ast-diff", true, "是否生成 AST 重命名 diff 报告")
	astPatch := flag.Bool("ast-patch", true, "是否生成 AST 重命名 patch")

	flag.Parse()

	ui.Banner()

	if *appID == "" || *input == "" {
		ui.PrintUsage()
		return
	}

	ui.Info("开始处理小程序: %s", *appID)
	ui.PrintDivider()
	cmd.ExecuteWithOptions(*appID, *input, *outputDir, *fileExt, *restoreDir, *pretty, *noClean, *save, *sensitive, *postman, *workspace, buildRewriteOptions(*astRename, *astDiff, *astPatch))
	ui.PrintDivider()
	ui.Success("处理完成!")
}

func buildRewriteOptions(astMode string, astDiff bool, astPatch bool) semantic.RewriteOptions {
	return semantic.RewriteOptions{
		ASTRename: semantic.ASTRenameOptions{
			Mode:          astMode,
			GenerateDiff:  astDiff,
			GeneratePatch: astPatch,
		},
	}
}

func printASTRenameNotice(options semantic.ASTRenameOptions) {
	lines := semantic.ASTRenameNoticeLines(options)
	if len(lines) == 0 {
		return
	}
	ui.Warning(lines[0])
	for _, line := range lines[1:] {
		ui.Info("   - %s", line)
	}
}
