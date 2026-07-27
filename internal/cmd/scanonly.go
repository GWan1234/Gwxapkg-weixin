package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/25smoking/Gwxapkg/internal/analyzer"
	"github.com/25smoking/Gwxapkg/internal/business"
	"github.com/25smoking/Gwxapkg/internal/formatter"
	"github.com/25smoking/Gwxapkg/internal/key"
	"github.com/25smoking/Gwxapkg/internal/packagecheck"
	"github.com/25smoking/Gwxapkg/internal/reporter"
	"github.com/25smoking/Gwxapkg/internal/scanner"
	"github.com/25smoking/Gwxapkg/internal/ui"
)

// ScanOnlyOptions 控制独立扫描行为。
type ScanOnlyOptions struct {
	Dir      string
	AppID    string
	Format   string
	OutputDir string
	Postman  bool
	RuleTier string
	BaseURL  string
	SARIF    bool
	OpenAPI  bool
}

// ScanOnly 对已解包目录执行独立敏感信息扫描，生成报告。
func ScanOnly(dir string, appID string, format string, outputDir string, postman bool) {
	ScanOnlyWithOptions(ScanOnlyOptions{
		Dir:       dir,
		AppID:     appID,
		Format:    format,
		OutputDir: outputDir,
		Postman:   postman,
	})
}

// ScanOnlyWithOptions 支持规则分层与扩展导出。
func ScanOnlyWithOptions(opts ScanOnlyOptions) {
	dir := opts.Dir
	if _, err := os.Stat(dir); err != nil {
		ui.Error("目录不存在: %s", dir)
		return
	}

	appID := opts.AppID
	if appID == "" {
		appID = filepath.Base(dir)
	}

	ui.Info("初始化扫描规则...")
	if err := key.InitRules(); err != nil {
		ui.Error("初始化规则失败: %v", err)
		return
	}

	scanOpts := scanner.DefaultScanOptions()
	scanOpts.Tiers = scanner.ParseRuleTierSpec(opts.RuleTier)
	scanner.SetGlobalScanOptions(scanOpts)
	if len(scanOpts.Tiers) > 0 {
		ui.Info("规则分层: %s", strings.Join(scanOpts.Tiers, ", "))
	}

	key.InitCollector(appID)
	collector := key.GetCollector()

	ui.Step(1, 2, "扫描目录: %s", dir)

	type scanJob struct {
		relPath string
		absPath string
		ext     string
	}

	var jobs []scanJob
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".gwxapkg" {
				return fs.SkipDir
			}
			return nil
		}
		relPath, _ := filepath.Rel(dir, path)
		relPath = filepath.ToSlash(relPath)
		if shouldSkipGeneratedArtifact(relPath) {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !isTextFile(ext) || !scanner.ShouldScanPath(relPath) {
			return nil
		}
		jobs = append(jobs, scanJob{relPath: relPath, absPath: path, ext: ext})
		return nil
	})
	if err != nil {
		ui.Warning("遍历目录出错: %v", err)
	}

	workers := runtime.NumCPU() * 2
	if workers < 4 {
		workers = 4
	}
	if workers > 32 {
		workers = 32
	}
	if len(jobs) < workers {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	jobCh := make(chan scanJob, workers)
	var wg sync.WaitGroup
	var fileCount int64

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				content, err := os.ReadFile(job.absPath)
				if err != nil {
					continue
				}
				atomic.AddInt64(&fileCount, 1)
				if job.ext == ".js" {
					result, analyzeErr := formatter.AnalyzeJavaScript(content, job.relPath)
					if analyzeErr == nil && result != nil {
						content = result.Content
						if result.IsObfuscated {
							collector.AddObfuscatedFile(scanner.ObfuscatedFile{
								FilePath:   job.relPath,
								Score:      result.Score,
								Techniques: result.Techniques,
								Status:     result.Status,
								Tag:        formatter.BuildObfuscatedTag(result),
							})
						}
					}
				}
				_ = scanner.ScanFileWithOptions(job.relPath, content, collector, scanOpts)
			}
		}()
	}

	for _, job := range jobs {
		jobCh <- job
	}
	close(jobCh)
	wg.Wait()

	totalFiles := int(atomic.LoadInt64(&fileCount))
	collector.SetTotalFiles(totalFiles)
	report := collector.GenerateReport()

	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = dir
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		ui.Error("创建报告输出目录失败: %v", err)
		key.ResetCollector()
		return
	}

	if completeness, err := packagecheck.AnalyzeAndWrite(dir, appID, nil); err != nil {
		ui.Warning("分包完整性检测失败: %v", err)
	} else if completeness != nil && completeness.Status != packagecheck.StatusUnknown {
		if filepath.Clean(outputDir) != filepath.Clean(dir) {
			if err := packagecheck.WriteReport(outputDir, completeness); err != nil {
				ui.Warning("复制分包完整性报告到输出目录失败: %v", err)
			}
		}
		if completeness.IsPartial() {
			ui.Warning("分包完整性: partial（已找到 %d/%d 个分包，缺失 %d 个，占位页面 %d 个）",
				completeness.FoundSubpackageCount,
				completeness.DeclaredSubpackageCount,
				completeness.MissingSubpackageCount,
				completeness.PlaceholderPageCount,
			)
		} else if completeness.IsFull() {
			ui.Success("分包完整性: full（已找到 %d/%d 个分包）",
				completeness.FoundSubpackageCount,
				completeness.DeclaredSubpackageCount,
			)
		}
	}

	ui.Step(2, 2, "生成报告...")

	if len(report.APIEndpoints) > 0 {
		apiEndpointMapReporter := reporter.NewAPIEndpointMapReporter()
		artifacts, err := apiEndpointMapReporter.Generate(report, dir, outputDir)
		if err != nil {
			ui.Warning("生成通用 API Endpoint 地图失败: %v", err)
		} else {
			ui.Success("通用 API Endpoint 地图: %s", artifacts.MarkdownPath)
		}
	}

	// 统一 API 地图（若磁盘上已有 semantic api_map 则合并）
	if artifacts, err := reporter.GenerateUnifiedAPIMap(dir, outputDir, report, nil); err != nil {
		ui.Warning("生成统一 API 地图失败: %v", err)
	} else if artifacts != nil {
		ui.Success("统一 API 地图: %s", artifacts.MarkdownPath)
		ui.Info("   - 合并端点: %d", artifacts.EndpointCount)
	}

	format := strings.ToLower(opts.Format)
	if format == "" {
		format = "both"
	}

	generated := 0
	if format == "json" || format == "both" || format == "sarif" {
		if format != "sarif" {
			path := filepath.Join(outputDir, "sensitive_report.json")
			jr := reporter.NewJSONReporter()
			if err := jr.Generate(report, path); err != nil {
				ui.Warning("生成 JSON 报告失败: %v", err)
			} else {
				ui.Success("JSON 报告: %s", path)
				generated++
			}
		}
	}
	if format == "excel" || format == "both" {
		path := filepath.Join(outputDir, "sensitive_report.xlsx")
		er := reporter.NewExcelReporter()
		if err := er.Generate(report, path); err != nil {
			ui.Warning("生成 Excel 报告失败: %v", err)
		} else {
			ui.Success("Excel 报告: %s", path)
			generated++
		}
	}
	if format == "html" || format == "both" {
		path := filepath.Join(outputDir, "sensitive_report.html")
		hr := reporter.NewHTMLReporter()
		if err := hr.Generate(report, path); err != nil {
			ui.Warning("生成 HTML 报告失败: %v", err)
		} else {
			ui.Success("HTML 报告: %s", path)
			generated++
		}
	}

	if opts.Postman {
		path := filepath.Join(outputDir, "api_collection.postman_collection.json")
		pr := reporter.NewPostmanReporter()
		if err := pr.GenerateWithOptions(report, path, reporter.PostmanOptions{BaseURL: opts.BaseURL}); err != nil {
			ui.Warning("生成 Postman Collection 失败: %v", err)
		} else {
			ui.Success("Postman Collection: %s", path)
		}
	}

	if opts.SARIF || format == "sarif" {
		path := filepath.Join(outputDir, "sensitive_report.sarif")
		if err := reporter.GenerateSARIF(report, path); err != nil {
			ui.Warning("生成 SARIF 报告失败: %v", err)
		} else {
			ui.Success("SARIF 报告: %s", path)
			generated++
		}
	}

	if opts.OpenAPI {
		path := filepath.Join(outputDir, "openapi.json")
		if err := reporter.GenerateOpenAPIFromDir(dir, path, opts.BaseURL); err != nil {
			ui.Warning("生成 OpenAPI 失败: %v", err)
		} else {
			ui.Success("OpenAPI: %s", path)
		}
	}

	routeManifest, routeErr := analyzer.AnalyzeMiniProgram(dir, appID)
	if routeErr != nil {
		ui.Warning("生成页面与路由地图失败: %v", routeErr)
	} else {
		rr := reporter.NewRouteReporter()
		artifacts, err := rr.Generate(routeManifest, outputDir)
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

	// 业务漏洞面（auth/idor/payment/upload/...）
	if surface, err := business.AnalyzeAndWrite(dir); err != nil {
		ui.Warning("生成业务漏洞面失败: %v", err)
	} else if surface != nil {
		// 输出目录若不同于扫描目录，复制一份
		if filepath.Clean(outputDir) != filepath.Clean(dir) {
			_ = business.WriteReport(outputDir, surface)
		}
		ui.Success("业务漏洞面: %s", surface.MarkdownPath)
		ui.Info("   - 打标接口: %d | 页面: %d | 假设: %d",
			len(surface.Endpoints), len(surface.Pages), len(surface.Hypotheses))
	}

	key.ResetCollector()

	if generated == 0 && !opts.Postman && !opts.OpenAPI {
		ui.Warning("未生成任何报告，请检查 -format 参数（json/excel/html/both/sarif）")
		return
	}

	fmt.Println()
	ui.Info("   - 接口数: %d", len(report.APIEndpoints))
	ui.Info("   - 混淆文件: %d", len(report.ObfuscatedFiles))
	ui.Info("   - 扫描文件数: %d", totalFiles)
	ui.Info("   - 总匹配数:   %d", report.Summary.TotalMatches)
	ui.Info("   - 去重后:     %d", report.Summary.UniqueMatches)
	ui.Info("   - 高风险: %d | 中风险: %d | 低风险: %d",
		report.Summary.HighRisk, report.Summary.MediumRisk, report.Summary.LowRisk)
}

// isTextFile 判断是否为需要扫描的文本文件
func isTextFile(ext string) bool {
	return scanner.IsScannableTextExt(ext)
}

func shouldSkipGeneratedArtifact(relPath string) bool {
	name := filepath.Base(relPath)
	switch name {
	case "sensitive_report.html",
		"sensitive_report.xlsx",
		"sensitive_report.json",
		"sensitive_report.sarif",
		"api_collection.postman_collection.json",
		"openapi.json",
		"route_manifest.json",
		"route_map.md",
		"route_map.mmd":
		return true
	default:
		return false
	}
}
