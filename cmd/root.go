package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/25smoking/Gwxapkg/internal/analyzer"
	"github.com/25smoking/Gwxapkg/internal/business"
	. "github.com/25smoking/Gwxapkg/internal/cmd"
	. "github.com/25smoking/Gwxapkg/internal/config"
	"github.com/25smoking/Gwxapkg/internal/dataflow"
	"github.com/25smoking/Gwxapkg/internal/doctor"
	"github.com/25smoking/Gwxapkg/internal/key"
	packmeta "github.com/25smoking/Gwxapkg/internal/pack"
	"github.com/25smoking/Gwxapkg/internal/packagecheck"
	"github.com/25smoking/Gwxapkg/internal/reporter"
	"github.com/25smoking/Gwxapkg/internal/restore"
	"github.com/25smoking/Gwxapkg/internal/scanner"
	"github.com/25smoking/Gwxapkg/internal/semantic"
	"github.com/25smoking/Gwxapkg/internal/ui"
	"github.com/25smoking/Gwxapkg/internal/util"
)

// ExecuteOptions 全量解包/分析流水线选项。
type ExecuteOptions struct {
	AppID         string
	Input         string
	OutputDir     string
	FileExt       string
	Restore       bool
	Pretty        bool
	NoClean       bool
	Save          bool
	Sensitive     bool
	Postman       bool
	Workspace     bool
	Fast          bool
	RuleTier      string
	BaseURL       string
	WriteDoctor   bool
	ExportSARIF   bool
	ExportOpenAPI bool
	Rewrite       semantic.RewriteOptions
}

func Execute(appID, input, outputDir, fileExt string, restoreDir bool, pretty bool, noClean bool, save bool, sensitive bool, postman bool, workspace bool) *packagecheck.Report {
	return ExecuteWithOptions(appID, input, outputDir, fileExt, restoreDir, pretty, noClean, save, sensitive, postman, workspace, semantic.DefaultRewriteOptions())
}

func ExecuteWithOptions(appID, input, outputDir, fileExt string, restoreDir bool, pretty bool, noClean bool, save bool, sensitive bool, postman bool, workspace bool, rewriteOptions semantic.RewriteOptions) *packagecheck.Report {
	return ExecutePipeline(ExecuteOptions{
		AppID:       appID,
		Input:       input,
		OutputDir:   outputDir,
		FileExt:     fileExt,
		Restore:     restoreDir,
		Pretty:      pretty,
		NoClean:     noClean,
		Save:        save,
		Sensitive:   sensitive,
		Postman:     postman,
		Workspace:   workspace,
		Rewrite:     rewriteOptions,
		WriteDoctor: true,
	})
}

// ExecutePipeline 执行完整解包分析流水线。
func ExecutePipeline(opts ExecuteOptions) *packagecheck.Report {
	appID := opts.AppID
	input := opts.Input
	outputDir := opts.OutputDir
	fileExt := opts.FileExt
	if fileExt == "" {
		fileExt = ".wxapkg"
	}
	restoreDir := opts.Restore
	pretty := opts.Pretty
	noClean := opts.NoClean
	save := opts.Save
	sensitive := opts.Sensitive
	postman := opts.Postman
	workspace := opts.Workspace
	fast := opts.Fast
	rewriteOptions := opts.Rewrite
	if fast {
		// 纯反编译对标模式：不初始化扫描器，也不执行后续审计产物链。
		sensitive = false
		postman = false
	}

	// 确定输出目录
	if outputDir == "" {
		outputDir = DetermineOutputDir(input, appID)
	}
	expandedOutputDir, err := util.ExpandHomePath(outputDir)
	if err != nil {
		ui.Warning("展开输出目录失败，继续使用原路径: %v", err)
	} else {
		outputDir = expandedOutputDir
	}
	// 后续分包恢复会并行执行。统一使用绝对路径，避免任一解析器因相对
	// 路径或当前工作目录变化而把文件写到 -out 的上一级。
	if absoluteOutputDir, absErr := filepath.Abs(outputDir); absErr != nil {
		ui.Error("解析输出目录失败: %v", absErr)
		return nil
	} else {
		outputDir = absoluteOutputDir
	}

	// 存储配置
	configManager := NewSharedConfigManager()
	configManager.Set("appID", appID)
	configManager.Set("input", input)
	configManager.Set("outputDir", outputDir)
	configManager.Set("fileExt", fileExt)
	configManager.Set("restoreDir", restoreDir)
	configManager.Set("pretty", pretty)
	configManager.Set("noClean", noClean)
	configManager.Set("save", save)
	configManager.Set("sensitive", sensitive)
	configManager.Set("postman", postman)
	configManager.Set("workspace", workspace)
	configManager.Set("fast", fast)
	configManager.Set("ruleTier", opts.RuleTier)
	configManager.Set("baseURL", opts.BaseURL)

	inputFiles := ParseInput(input, fileExt)

	if len(inputFiles) == 0 {
		ui.Warning("未找到任何文件")
		return nil
	}

	// 如果需要敏感扫描或 Postman 导出，初始化规则与收集器
	if sensitive || postman {
		if err := key.InitRules(); err != nil {
			ui.Warning("初始化扫描规则失败: %v", err)
			sensitive = false
			postman = false
		} else {
			scanOpts := scanner.DefaultScanOptions()
			scanOpts.Tiers = scanner.ParseRuleTierSpec(opts.RuleTier)
			scanner.SetGlobalScanOptions(scanOpts)
			if len(scanOpts.Tiers) > 0 {
				ui.Info("规则分层: %s", strings.Join(scanOpts.Tiers, ", "))
			}
			key.InitCollector(appID)
		}
	}

	// 显示步骤信息
	ui.Step(1, 2, "解包 wxapkg 文件...")

	// 创建进度条
	bar := ui.NewProgressBar(len(inputFiles), "解包中")

	var wg sync.WaitGroup
	var errCount int32
	errChan := make(chan error, len(inputFiles))

	for _, inputFile := range inputFiles {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			err := ProcessFile(file, outputDir, appID, save, workspace)
			if err != nil {
				atomic.AddInt32(&errCount, 1)
				errChan <- err
			}
			bar.Add(1)
		}(inputFile)
	}
	wg.Wait()
	close(errChan)

	for err := range errChan {
		ui.Error("%v", err)
	}

	// 显示解包结果
	if errCount > 0 {
		ui.Warning("解包完成，%d 个文件处理失败", errCount)
	}

	// 为保留原始包内容的场景生成 manifest，方便后续精确回包
	if workspace || !restoreDir || noClean {
		if err := packmeta.WritePackageManifest(outputDir, appID, GetWxapkgManager()); err != nil {
			ui.Warning("写入回包 manifest 失败: %v", err)
		}
	}

	// 还原工程目录结构
	ui.Step(2, 2, "还原工程结构...")
	restore.ProjectStructure(outputDir, restoreDir)
	if fast {
		fmt.Println()
		ui.Success("快速反编译完成: %s", filepath.Clean(outputDir))
		ui.Info("   - 已跳过敏感扫描、语义重写、路由/业务面与 doctor 后处理")
		return nil
	}

	var semanticAPIMap *semantic.APIMapReport
	if restoreDir {
		printASTRenameNotice(rewriteOptions.ASTRename)
		semanticReport, err := semantic.RewriteProjectWithOptions(outputDir, rewriteOptions)
		if err != nil {
			ui.Warning("源码级语义反混淆失败: %v", err)
		} else {
			if collector := key.GetCollector(); collector != nil {
				collector.RewriteFilePaths(semanticReport.PathMap)
			}
			if semanticReport.RenamedCount > 0 || semanticReport.SourceMapRecovered > 0 {
				ui.Success("源码语义映射: %s", filepath.Join(outputDir, ".gwxapkg", "semantic_module_map.json"))
				ui.Info("   - 语义重命名: %d | require 重写: %d | SourceMap 源码: %d",
					semanticReport.RenamedCount,
					semanticReport.RewrittenRequireCount,
					semanticReport.SourceMapRecovered,
				)
			}
			if semanticReport.APIEndpointCount > 0 {
				ui.Success("API 地图: %s", filepath.Join(outputDir, ".gwxapkg", "api_map.md"))
				ui.Info("   - API 函数: %d | 细拆模块: %d",
					semanticReport.APIEndpointCount,
					semanticReport.APISplitCount,
				)
				ui.Success("API 调用链: %s", filepath.Join(outputDir, ".gwxapkg", "api_call_chain.md"))
				ui.Success("API 伪代码: %s", filepath.Join(outputDir, ".gwxapkg", "api_pseudo.md"))
			}
			if semanticReport.ASTRenamedCount > 0 {
				ui.Success("AST 重命名报告: %s", filepath.Join(outputDir, ".gwxapkg", "ast_rename_map.json"))
				ui.Info("   - AST 重命名: %d | 文件数: %d",
					semanticReport.ASTRenamedCount,
					semanticReport.ASTRenamedFiles,
				)
			}
			// 尝试加载 semantic api_map 供统一地图合并
			if loaded, loadErr := loadSemanticAPIMap(outputDir); loadErr == nil {
				semanticAPIMap = loaded
			}
		}
	}

	var completenessReport *packagecheck.Report
	if restoreDir {
		report, err := packagecheck.AnalyzeAndWrite(outputDir, appID, inputFiles)
		if err != nil {
			ui.Warning("分包完整性检测失败: %v", err)
		} else if report != nil && report.Status != packagecheck.StatusUnknown {
			completenessReport = report
			printPackageCompleteness(report, outputDir)
		}
	}

	// 输出结果目录
	fmt.Println()
	ui.Success("输出目录: %s", filepath.Clean(outputDir))

	collector := key.GetCollector()
	var scanReport *scanner.ScanReport
	if collector != nil {
		// 注意：此处统计的是输入包数量；文件级扫描数在 unpack worker 内累计不完整，保持兼容
		collector.SetTotalFiles(len(inputFiles))
		scanReport = collector.GenerateReport()

		if len(scanReport.APIEndpoints) > 0 {
			apiEndpointMapReporter := reporter.NewAPIEndpointMapReporter()
			artifacts, err := apiEndpointMapReporter.Generate(scanReport, outputDir, outputDir)
			if err != nil {
				ui.Warning("生成通用 API Endpoint 地图失败: %v", err)
			} else {
				ui.Success("通用 API Endpoint 地图: %s", artifacts.MarkdownPath)
				ui.Info("   - 通用 Endpoint: %d", len(scanReport.APIEndpoints))
			}
		}

		if artifacts, err := reporter.GenerateUnifiedAPIMap(outputDir, outputDir, scanReport, semanticAPIMap); err != nil {
			ui.Warning("生成统一 API 地图失败: %v", err)
		} else if artifacts != nil {
			ui.Success("统一 API 地图: %s", artifacts.MarkdownPath)
			ui.Info("   - 统一端点: %d (semantic=%d http=%d merged=%d)",
				artifacts.EndpointCount, artifacts.SemanticCount, artifacts.HTTPCount, artifacts.MergedCount)
		}

		if sensitive {
			jsonReporter := reporter.NewJSONReporter()
			jsonPath := filepath.Join(outputDir, "sensitive_report.json")
			if err := jsonReporter.Generate(scanReport, jsonPath); err != nil {
				ui.Warning("生成 JSON 报告失败: %v", err)
			} else {
				ui.Success("JSON 报告: %s", jsonPath)
			}

			excelReporter := reporter.NewExcelReporter()
			excelPath := filepath.Join(outputDir, "sensitive_report.xlsx")
			if err := excelReporter.Generate(scanReport, excelPath); err != nil {
				ui.Warning("生成 Excel 报告失败: %v", err)
			} else {
				ui.Success("Excel 报告: %s", excelPath)
			}

			htmlReporter := reporter.NewHTMLReporter()
			htmlPath := filepath.Join(outputDir, "sensitive_report.html")
			if err := htmlReporter.Generate(scanReport, htmlPath); err != nil {
				ui.Warning("生成 HTML 报告失败: %v", err)
			} else {
				ui.Success("HTML 报告: %s", htmlPath)
			}
		}

		if postman {
			postmanReporter := reporter.NewPostmanReporter()
			postmanPath := filepath.Join(outputDir, "api_collection.postman_collection.json")
			if err := postmanReporter.GenerateWithOptions(scanReport, postmanPath, reporter.PostmanOptions{BaseURL: opts.BaseURL}); err != nil {
				ui.Warning("生成 Postman Collection 失败: %v", err)
			} else {
				ui.Success("Postman Collection: %s", postmanPath)
			}
		}

		if opts.ExportSARIF && scanReport != nil {
			sarifPath := filepath.Join(outputDir, "sensitive_report.sarif")
			if err := reporter.GenerateSARIF(scanReport, sarifPath); err != nil {
				ui.Warning("生成 SARIF 失败: %v", err)
			} else {
				ui.Success("SARIF 报告: %s", sarifPath)
			}
		}

		if opts.ExportOpenAPI {
			openAPIPath := filepath.Join(outputDir, "openapi.json")
			if err := reporter.GenerateOpenAPIFromDir(outputDir, openAPIPath, opts.BaseURL); err != nil {
				ui.Warning("生成 OpenAPI 失败: %v", err)
			} else {
				ui.Success("OpenAPI: %s", openAPIPath)
			}
		}

		if sensitive || postman {
			ui.Info("   - 接口数: %d", len(scanReport.APIEndpoints))
			ui.Info("   - 混淆文件: %d", len(scanReport.ObfuscatedFiles))
		}
		if sensitive {
			ui.Info("   - 总匹配数: %d", scanReport.Summary.TotalMatches)
			ui.Info("   - 去重后: %d", scanReport.Summary.UniqueMatches)
			ui.Info("   - 高风险: %d | 中风险: %d | 低风险: %d",
				scanReport.Summary.HighRisk, scanReport.Summary.MediumRisk, scanReport.Summary.LowRisk)
		}

		key.ResetCollector()
	}

	if restoreDir {
		routeManifest, routeErr := analyzer.AnalyzeMiniProgram(outputDir, appID)
		if routeErr != nil {
			ui.Warning("生成页面与路由地图失败: %v", routeErr)
		} else {
			routeReporter := reporter.NewRouteReporter()
			artifacts, err := routeReporter.Generate(routeManifest, outputDir)
			if err != nil {
				ui.Warning("写入页面与路由地图失败: %v", err)
			} else {
				ui.Success("页面路由清单: %s", artifacts.ManifestPath)
				ui.Success("页面路由说明: %s", artifacts.MarkdownPath)
				ui.Success("页面路由图: %s", artifacts.MermaidPath)
				ui.Info("   - 页面数: %d | 跳转边: %d | 调用链边: %d | 共享助手: %d | TabBar: %d",
					routeManifest.Summary.TotalPages,
					routeManifest.Summary.NavigationEdgeCount,
					routeManifest.Summary.CallChainEdgeCount,
					routeManifest.Summary.SharedRouterHelperCount,
					routeManifest.Summary.TabBarPages,
				)
			}
		}
	}

	if restoreDir {
		if df, err := dataflow.AnalyzeAndWrite(outputDir); err != nil {
			ui.Warning("生成 dataflow hints 失败: %v", err)
		} else if df != nil && df.HintCount > 0 {
			ui.Success("数据流线索: %s (%d)", df.JSONPath, df.HintCount)
		}
	}

	// 业务漏洞面：依赖 unified map + route_manifest，放在路由分析之后
	if restoreDir {
		if surface, err := business.AnalyzeAndWrite(outputDir); err != nil {
			ui.Warning("生成业务漏洞面失败: %v", err)
		} else if surface != nil {
			ui.Success("业务漏洞面: %s", surface.MarkdownPath)
			ui.Info("   - 打标接口: %d | 页面: %d | 假设: %d",
				len(surface.Endpoints), len(surface.Pages), len(surface.Hypotheses))
		}
	}

	if opts.WriteDoctor || restoreDir {
		if health, err := doctor.AnalyzeAndWrite(outputDir); err != nil {
			ui.Warning("生成 doctor 报告失败: %v", err)
		} else if health != nil {
			ui.Success("Doctor 报告: %s (status=%s)", health.MarkdownPath, health.Status)
		}
	}

	return completenessReport
}

func loadSemanticAPIMap(rootDir string) (*semantic.APIMapReport, error) {
	return semantic.ReadAPIMap(rootDir)
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

func printPackageCompleteness(report *packagecheck.Report, outputDir string) {
	if report.IsFull() {
		ui.Success("分包完整性: full（已找到 %d/%d 个分包）",
			report.FoundSubpackageCount,
			report.DeclaredSubpackageCount,
		)
	} else if report.IsPartial() {
		ui.Warning("分包完整性: partial（已找到 %d/%d 个分包，缺失 %d 个，占位页面 %d 个）",
			report.FoundSubpackageCount,
			report.DeclaredSubpackageCount,
			report.MissingSubpackageCount,
			report.PlaceholderPageCount,
		)
		ui.Info("   - 当前输出目录包含完整路由骨架，但缺失分包下的占位页面不代表真实源码")
	}
	ui.Success("分包完整性报告: %s", filepath.Join(outputDir, ".gwxapkg", "package_completeness.md"))
}
