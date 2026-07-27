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
	"github.com/25smoking/Gwxapkg/internal/audit"
	internalcmd "github.com/25smoking/Gwxapkg/internal/cmd"
	"github.com/25smoking/Gwxapkg/internal/configfile"
	"github.com/25smoking/Gwxapkg/internal/doctor"
	"github.com/25smoking/Gwxapkg/internal/locator"
	"github.com/25smoking/Gwxapkg/internal/pack"
	"github.com/25smoking/Gwxapkg/internal/packagecheck"
	"github.com/25smoking/Gwxapkg/internal/semantic"
	"github.com/25smoking/Gwxapkg/internal/ui"
	"github.com/25smoking/Gwxapkg/internal/util"
	"github.com/25smoking/Gwxapkg/internal/validate"
)

// 进程级配置（项目/用户 yaml），CLI 显式参数优先覆盖。
var loadedConfig *configfile.Config

// 可通过 -ldflags "-X main.version=..." 注入
var version = "2.8.0"

func main() {
	if cfg, path, err := configfile.Load(); err != nil {
		// 配置损坏时仅警告，不阻断
		fmt.Fprintf(os.Stderr, "warning: load config %s: %v\n", path, err)
	} else {
		loadedConfig = cfg
		if path != "" {
			// 安静加载，需要时可 --verbose 扩展
			_ = path
		}
	}

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
		case "doctor", "summary":
			handleDoctorCommand(os.Args[2:])
			return
		case "audit":
			handleAuditCommand(os.Args[2:])
			return
		case "validate", "live":
			handleValidateCommand(os.Args[2:])
			return
		case "version", "-version", "--version":
			fmt.Printf("gwxapkg %s\n", version)
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
	watch := allFlags.String("watch", "", "分包监听: listen(只监听)/auto(捕获后自动解包)；布尔 true 等同 listen")
	ruleTier := allFlags.String("rule-tier", "all", "敏感规则层级: all/high/medium 或 critical,high")
	baseURL := allFlags.String("base-url", "", "Postman/OpenAPI 基础 URL")
	sarif := allFlags.Bool("sarif", false, "是否导出 SARIF 报告")
	openapi := allFlags.Bool("openapi", false, "是否导出 OpenAPI 文档")
	astRename := allFlags.String("ast-rename", semantic.ASTRenameModeDeep, "AST 重命名模式: off/report/safe/deep")
	astDiff := allFlags.Bool("ast-diff", true, "是否生成 AST 重命名 diff 报告")
	astPatch := allFlags.Bool("ast-patch", true, "是否生成 AST 重命名 patch")

	allFlags.Parse(normalizeBareWatchArgs(args))
	watchMode := normalizeWatchMode(*watch)
	*ruleTier = defaultRuleTier(*ruleTier)
	*baseURL = defaultBaseURL(*baseURL)

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
	if watchMode != "" && len(appIDs) > 1 {
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
		if watchMode != "" {
			report := buildWatchReport(id, matched.Path, resolvedOutputDir)
			watchPackageDownloads(WatchOptions{
				AppID:     id,
				InputDir:  matched.Path,
				OutputDir: resolvedOutputDir,
				Mode:      watchMode,
				Report:    report,
				Unpack: cmd.ExecuteOptions{
					AppID:         id,
					Input:         matched.Path,
					OutputDir:     resolvedOutputDir,
					FileExt:       ".wxapkg",
					Restore:       *restoreDir,
					Pretty:        *pretty,
					NoClean:       *noClean,
					Save:          *save,
					Sensitive:     *sensitive,
					Postman:       *postman,
					Workspace:     *workspace,
					RuleTier:      *ruleTier,
					BaseURL:       *baseURL,
					ExportSARIF:   *sarif,
					ExportOpenAPI: *openapi,
					WriteDoctor:   true,
					Rewrite:       buildRewriteOptions(*astRename, *astDiff, *astPatch),
				},
			})
			continue
		}

		rewriteOptions := buildRewriteOptions(*astRename, *astDiff, *astPatch)
		cmd.ExecutePipeline(cmd.ExecuteOptions{
			AppID:         id,
			Input:         matched.Path,
			OutputDir:     resolvedOutputDir,
			FileExt:       ".wxapkg",
			Restore:       *restoreDir,
			Pretty:        *pretty,
			NoClean:       *noClean,
			Save:          *save,
			Sensitive:     *sensitive,
			Postman:       *postman,
			Workspace:     *workspace,
			RuleTier:      *ruleTier,
			BaseURL:       *baseURL,
			ExportSARIF:   *sarif,
			ExportOpenAPI: *openapi,
			WriteDoctor:   true,
			Rewrite:       rewriteOptions,
		})
	}

	ui.PrintDivider()
	ui.Success("全部处理完成! (%d 个小程序)", len(appIDs))
}

// handleScanCommand 处理 scan 子命令（交互式选择解包）
func handleScanCommand(args []string) {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
	verbose := scanFlags.Bool("verbose", false, "显示扫描候选路径诊断")
	postman := scanFlags.Bool("postman", false, "是否导出 Postman Collection")
	watch := scanFlags.String("watch", "", "分包监听: listen/auto；布尔 true 等同 listen")
	ruleTier := scanFlags.String("rule-tier", "all", "敏感规则层级: all/high/medium 或 critical,high")
	baseURL := scanFlags.String("base-url", "", "Postman/OpenAPI 基础 URL")
	astRename := scanFlags.String("ast-rename", semantic.ASTRenameModeDeep, "AST 重命名模式: off/report/safe/deep")
	astDiff := scanFlags.Bool("ast-diff", true, "是否生成 AST 重命名 diff 报告")
	astPatch := scanFlags.Bool("ast-patch", true, "是否生成 AST 重命名 patch")
	scanFlags.Parse(normalizeBareWatchArgs(args))
	watchMode := normalizeWatchMode(*watch)
	*ruleTier = defaultRuleTier(*ruleTier)
	*baseURL = defaultBaseURL(*baseURL)

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
	if watchMode != "" {
		ui.Info("完整性报告读取目录: %s", outputDir)
	} else {
		ui.Info("解包结果将保存到: %s", outputDir)
	}
	fmt.Println()

	if watchMode != "" {
		report := buildWatchReport(selected.AppID, selected.Path, outputDir)
		watchPackageDownloads(WatchOptions{
			AppID:     selected.AppID,
			InputDir:  selected.Path,
			OutputDir: outputDir,
			Mode:      watchMode,
			Report:    report,
			Unpack: cmd.ExecuteOptions{
				AppID:       selected.AppID,
				Input:       selected.Path,
				OutputDir:   outputDir,
				FileExt:     ".wxapkg",
				Restore:     true,
				Pretty:      true,
				Sensitive:   true,
				Postman:     *postman,
				RuleTier:    *ruleTier,
				BaseURL:     *baseURL,
				WriteDoctor: true,
				Rewrite:     buildRewriteOptions(*astRename, *astDiff, *astPatch),
			},
		})
		ui.PrintDivider()
		ui.Success("watch 已结束")
		return
	}

	// 直接进入解包流程（复用 all 命令的默认参数）
	rewriteOptions := buildRewriteOptions(*astRename, *astDiff, *astPatch)
	cmd.ExecutePipeline(cmd.ExecuteOptions{
		AppID:       selected.AppID,
		Input:       selected.Path,
		OutputDir:   outputDir,
		FileExt:     ".wxapkg",
		Restore:     true,
		Pretty:      true,
		Sensitive:   true,
		Postman:     *postman,
		RuleTier:    *ruleTier,
		BaseURL:     *baseURL,
		WriteDoctor: true,
		Rewrite:     rewriteOptions,
	})

	ui.PrintDivider()
	ui.Success("处理完成!")
}

// WatchOptions 控制分包监听行为。
type WatchOptions struct {
	AppID     string
	InputDir  string
	OutputDir string
	Mode      string // listen | auto
	Report    *packagecheck.Report
	Unpack    cmd.ExecuteOptions
}

func normalizeWatchMode(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "", "false", "0", "off", "no":
		return ""
	case "true", "1", "yes", "listen", "watch":
		return "listen"
	case "auto":
		return "auto"
	default:
		return value
	}
}

// normalizeBareWatchArgs 将裸 -watch 规范为 -watch=listen，兼容旧用法。
func normalizeBareWatchArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-watch" || arg == "--watch" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				out = append(out, "-watch=listen")
				continue
			}
		}
		out = append(out, arg)
	}
	return out
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

func watchPackageDownloads(opts WatchOptions) {
	appID := opts.AppID
	inputDir := opts.InputDir
	outputDir := opts.OutputDir
	report := opts.Report
	mode := opts.Mode
	if mode == "" {
		mode = "listen"
	}

	if report != nil && report.IsFull() {
		ui.Success("分包已完整，无需进入 watch")
		return
	}

	ui.Warning("进入缺失分包监控模式: %s (mode=%s)", appID, mode)
	ui.Info("   - 请在微信中打开缺失功能页，客户端下载新分包后工具会自动捕获")
	ui.Info("   - 监听目录: %s", inputDir)
	if mode == "listen" {
		ui.Info("   - listen 模式只提示，不自动解包；退出后请运行普通 scan/all")
	} else if mode == "auto" {
		ui.Info("   - auto 模式会在捕获新包后自动重新解包合并")
	}
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

	var unpacking bool

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
			// 防抖：等待文件写稳定
			time.Sleep(1500 * time.Millisecond)
			report = buildWatchReport(appID, inputDir, outputDir)
			printWatchProgress(report, len(known))

			if mode == "auto" && !unpacking {
				unpacking = true
				ui.Info("auto: 开始自动重新解包合并...")
				opts.Unpack.Input = inputDir
				opts.Unpack.OutputDir = outputDir
				opts.Unpack.AppID = appID
				cmd.ExecutePipeline(opts.Unpack)
				report = buildWatchReport(appID, inputDir, outputDir)
				if report != nil && report.IsFull() {
					ui.Success("auto: 分包已完整，输出目录: %s", outputDir)
				} else {
					ui.Info("auto: 解包完成，仍可能缺失部分分包，继续监听...")
				}
				// 刷新已知文件集合，避免解包期间新下载被忽略
				known = snapshotWxapkgFiles(inputDir)
				unpacking = false
			}
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
	format := f.String("format", "both", "报告格式: json / excel / html / both / sarif")
	out := f.String("out", "", "报告输出目录（默认与 -dir 相同）")
	postman := f.Bool("postman", false, "是否导出 Postman Collection")
	ruleTier := f.String("rule-tier", "all", "敏感规则层级: all/high/medium 或 critical,high")
	baseURL := f.String("base-url", "", "Postman/OpenAPI 基础 URL")
	sarif := f.Bool("sarif", false, "是否导出 SARIF 报告")
	openapi := f.Bool("openapi", false, "是否导出 OpenAPI 文档")
	f.Parse(args)
	*ruleTier = defaultRuleTier(*ruleTier)
	*baseURL = defaultBaseURL(*baseURL)

	ui.Banner()

	// 支持位置参数
	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("请指定目录: ./Gwxapkg scan-only -dir=<已解包目录>")
		return
	}

	internalcmd.ScanOnlyWithOptions(internalcmd.ScanOnlyOptions{
		Dir:       *dir,
		AppID:     *appID,
		Format:    *format,
		OutputDir: *out,
		Postman:   *postman,
		RuleTier:  *ruleTier,
		BaseURL:   *baseURL,
		SARIF:     *sarif,
		OpenAPI:   *openapi,
	})
}

func handleDoctorCommand(args []string) {
	f := flag.NewFlagSet("doctor", flag.ExitOnError)
	dir := f.String("dir", "", "已解包目录路径")
	f.Parse(args)

	ui.Banner()
	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("请指定目录: ./gwxapkg doctor -dir=<已解包目录>")
		return
	}
	expanded, err := util.ExpandHomePath(*dir)
	if err != nil {
		expanded = *dir
	}
	report, err := doctor.AnalyzeAndWrite(expanded)
	if err != nil {
		ui.Error("doctor 失败: %v", err)
		return
	}
	ui.Success("Doctor 状态: %s", report.Status)
	ui.Info("   - Semantic API: %d | HTTP API: %d | Unified: %d",
		report.SemanticEndpointCount, report.HTTPEndpointCount, report.UnifiedEndpointCount)
	ui.Info("   - 敏感命中: %d | AST skipped: %d", report.SensitiveMatchCount, report.ASTSkippedFiles)
	if report.PackageStatus != "" {
		ui.Info("   - 分包状态: %s (missing=%d)", report.PackageStatus, report.MissingSubpackages)
	}
	for _, gap := range report.Gaps {
		ui.Warning("缺口: %s", gap)
	}
	for _, s := range report.Suggestions {
		ui.Info("建议: %s", s)
	}
	ui.Success("报告: %s", report.MarkdownPath)
}

func handleAuditCommand(args []string) {
	f := flag.NewFlagSet("audit", flag.ExitOnError)
	dir := f.String("dir", "", "已解包目录路径")
	fix := f.Bool("fix", false, "缺失产物时提示补跑命令（不自动执行重分析，避免循环依赖）")
	burpFile := f.String("burp-file", "", "可选 Burp 原始请求文件（仅记录到 manifest）")
	f.Parse(args)

	ui.Banner()
	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("请指定目录: ./gwxapkg audit -dir=<已解包目录>")
		return
	}
	expanded, err := util.ExpandHomePath(*dir)
	if err != nil {
		expanded = *dir
	}

	// -fix=true 时尽力补跑 scan-only / semantic 缺失项
	if *fix {
		health, _ := doctor.Analyze(expanded)
		if health != nil {
			needScan := !artifactPresent(health, "sensitive_report")
			needSemantic := !artifactPresent(health, "api_map") && !artifactPresent(health, "semantic_module_map")
			if needSemantic {
				ui.Info("fix: 补跑 semantic...")
				if _, err := semantic.RewriteProjectWithOptions(expanded, semantic.DefaultRewriteOptions()); err != nil {
					ui.Warning("fix semantic 失败: %v", err)
				}
			}
			if needScan {
				ui.Info("fix: 补跑 scan-only...")
				internalcmd.ScanOnlyWithOptions(internalcmd.ScanOnlyOptions{
					Dir:     expanded,
					Format:  "both",
					Postman: false,
				})
			}
		}
	}

	result, err := audit.Run(audit.Options{
		Dir:      expanded,
		Fix:      *fix,
		BurpFile: *burpFile,
		Version:  version,
	})
	if err != nil {
		ui.Error("audit 失败: %v", err)
		return
	}
	ui.Success("审计骨架已生成: %s", result.AuditDir)
	ui.Info("   - doctor=%s | findings=%d", result.DoctorStatus, result.FindingCount)
	ui.Success("报告: %s", result.ReportPath)
	ui.Success("Findings: %s", result.FindingsPath)
	ui.Success("覆盖缺口: %s", result.CoveragePath)
}

func handleValidateCommand(args []string) {
	f := flag.NewFlagSet("validate", flag.ExitOnError)
	dir := f.String("dir", "", "已解包目录（含 business_surface / ai_audit）")
	baseURL := f.String("base-url", "", "API 根地址，如 https://api.example.com（必填）")
	authorize := f.Bool("i-authorize-live", false, "我确认已获充分授权，允许对 base-url 发送探测请求")
	dryRun := f.Bool("dry-run", false, "只生成探测计划，不发送请求")
	token := f.String("token", "", "登录 token（可选，用于鉴权基线/IDOR）")
	tokenB := f.String("token-b", "", "第二身份 token（可选，IDOR 对比）")
	tokenHeader := f.String("token-header", "Authorization", "鉴权请求头名")
	tokenPrefix := f.String("token-prefix", "", "鉴权头前缀，如 Bearer ")
	probeIDs := f.String("probe-ids", "1,2,99999999", "对象级探测 ID 列表，逗号分隔")
	allowHosts := f.String("allow-hosts", "", "额外允许的 Host，逗号分隔（默认仅 base-url 的 host）")
	surfaces := f.String("surfaces", "", "只验证这些业务面，逗号分隔：auth,idor,payment,upload")
	maxReq := f.Int("max-requests", 80, "最大请求数")
	qps := f.Float64("qps", 2, "每秒请求上限")
	timeout := f.Int("timeout-sec", 12, "单请求超时秒数")
	insecure := f.Bool("insecure", false, "跳过 TLS 证书校验")
	includeUnsafe := f.Bool("include-unsafe", false, "放宽部分写接口探测（仍禁止短信发送/下单/删除）")
	f.Parse(args)

	ui.Banner()
	if *dir == "" && f.NArg() > 0 {
		*dir = f.Arg(0)
	}
	if *dir == "" {
		ui.Error("用法: ./gwxapkg validate -dir=<已解包目录> -base-url=https://api.xxx.com -i-authorize-live=true")
		ui.Info("可选: -token=... -token-b=... -probe-ids=1,2 -dry-run -surfaces=idor,auth")
		return
	}
	expanded, err := util.ExpandHomePath(*dir)
	if err != nil {
		expanded = *dir
	}
	*baseURL = defaultBaseURL(*baseURL)

	splitCSV := func(s string) []string {
		if strings.TrimSpace(s) == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}

	if !*authorize {
		ui.Error("活体验证默认关闭。若你已获充分授权，请显式添加: -i-authorize-live=true")
		ui.Info("可先 -dry-run 查看将探测哪些接口（仍需 authorize 标志以生成计划时可同时加 dry-run）")
		// dry-run 也要求 authorize，避免误用习惯；但允许 dry-run + authorize 不发包
		return
	}

	ui.Warning("即将对授权目标发起活体探测: %s", *baseURL)
	if *dryRun {
		ui.Info("dry-run 模式：只出计划，不发送 HTTP 请求")
	}

	report, err := validate.Run(validate.Options{
		Dir:            expanded,
		BaseURL:        *baseURL,
		IAuthorizeLive: *authorize,
		DryRun:         *dryRun,
		Token:          *token,
		TokenB:         *tokenB,
		TokenHeader:    *tokenHeader,
		TokenPrefix:    *tokenPrefix,
		ProbeIDs:       splitCSV(*probeIDs),
		AllowHosts:     splitCSV(*allowHosts),
		Surfaces:       splitCSV(*surfaces),
		MaxRequests:    *maxReq,
		QPS:            *qps,
		Timeout:        time.Duration(*timeout) * time.Second,
		InsecureTLS:    *insecure,
		IncludeUnsafe:  *includeUnsafe,
	})
	if err != nil {
		ui.Error("validate 失败: %v", err)
		return
	}

	ui.Success("活体验证完成: requests=%d plans=%d dry-run=%v", report.RequestCount, report.PlanCount, report.DryRun)
	confirmed, confStatic, unauthDenied, authUntested, fp, inconcl, skipped := 0, 0, 0, 0, 0, 0, 0
	for _, v := range report.HypothesisVerdicts {
		switch v.Status {
		case validate.StatusConfirmed:
			confirmed++
			ui.Warning("[%s] %s → CONFIRMED(live): %s", v.ID, v.Surface, v.Summary)
		case validate.StatusConfirmedStatic:
			confStatic++
			ui.Warning("[%s] %s → CONFIRMED_STATIC: %s", v.ID, v.Surface, v.Summary)
		case validate.StatusUnauthDenied:
			unauthDenied++
			ui.Info("[%s] %s → unauth_denied（匿名被拒，≠无洞）: %s", v.ID, v.Surface, v.Summary)
		case validate.StatusAuthIDORUntested:
			authUntested++
			ui.Info("[%s] %s → auth_idor_untested（需 -token）: %s", v.ID, v.Surface, v.Summary)
		case validate.StatusFalsePositive:
			fp++
			ui.Info("[%s] %s → false_positive: %s", v.ID, v.Surface, v.Summary)
		case validate.StatusSkipped:
			skipped++
			ui.Info("[%s] %s → skipped: %s", v.ID, v.Surface, v.Summary)
		default:
			inconcl++
			ui.Info("[%s] %s → inconclusive: %s", v.ID, v.Surface, v.Summary)
		}
	}
	ui.Info("假设汇总: confirmed=%d confirmed_static=%d unauth_denied=%d auth_idor_untested=%d false_positive=%d inconclusive=%d skipped=%d",
		confirmed, confStatic, unauthDenied, authUntested, fp, inconcl, skipped)
	if len(report.FindingUpdates) > 0 {
		ui.Success("已回写 findings 状态: %d 条", len(report.FindingUpdates))
	}
	ui.Success("报告: %s", report.MarkdownPath)
	if report.LogPath != "" {
		ui.Success("请求日志: %s", report.LogPath)
	}
}

func artifactPresent(report *doctor.HealthReport, name string) bool {
	if report == nil {
		return false
	}
	for _, a := range report.Artifacts {
		if a.Name == name {
			return a.Exists
		}
	}
	return false
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
	ruleTier := flag.String("rule-tier", "all", "敏感规则层级: all/high/medium 或 critical,high")
	baseURL := flag.String("base-url", "", "Postman/OpenAPI 基础 URL")
	sarif := flag.Bool("sarif", false, "是否导出 SARIF 报告")
	openapi := flag.Bool("openapi", false, "是否导出 OpenAPI 文档")
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
	cmd.ExecutePipeline(cmd.ExecuteOptions{
		AppID:         *appID,
		Input:         *input,
		OutputDir:     *outputDir,
		FileExt:       *fileExt,
		Restore:       *restoreDir,
		Pretty:        *pretty,
		NoClean:       *noClean,
		Save:          *save,
		Sensitive:     *sensitive,
		Postman:       *postman,
		Workspace:     *workspace,
		RuleTier:      *ruleTier,
		BaseURL:       *baseURL,
		ExportSARIF:   *sarif,
		ExportOpenAPI: *openapi,
		WriteDoctor:   true,
		Rewrite:       buildRewriteOptions(*astRename, *astDiff, *astPatch),
	})
	ui.PrintDivider()
	ui.Success("处理完成!")
}

func buildRewriteOptions(astMode string, astDiff bool, astPatch bool) semantic.RewriteOptions {
	opts := semantic.DefaultASTRenameOptions()
	opts.Mode = astMode
	opts.GenerateDiff = astDiff
	opts.GeneratePatch = astPatch
	return semantic.RewriteOptions{ASTRename: opts}
}

func defaultRuleTier(cli string) string {
	if cli != "all" {
		return cli
	}
	if loadedConfig != nil && strings.TrimSpace(loadedConfig.RuleTier) != "" {
		return loadedConfig.RuleTier
	}
	return cli
}

func defaultBaseURL(cli string) string {
	if strings.TrimSpace(cli) != "" {
		return cli
	}
	if loadedConfig != nil {
		return loadedConfig.BaseURL
	}
	return ""
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
