package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/25smoking/Gwxapkg/internal/analyzer"
)

type RouteArtifacts struct {
	ManifestPath string
	MarkdownPath string
	MermaidPath  string
}

// RouteReporter 负责输出页面与路由分析结果。
type RouteReporter struct{}

func NewRouteReporter() *RouteReporter {
	return &RouteReporter{}
}

func (r *RouteReporter) Generate(manifest *analyzer.RouteManifest, outputDir string) (*RouteArtifacts, error) {
	if manifest == nil {
		return nil, fmt.Errorf("route manifest 不能为空")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("创建输出目录失败: %w", err)
	}

	artifacts := &RouteArtifacts{
		ManifestPath: filepath.Join(outputDir, "route_manifest.json"),
		MarkdownPath: filepath.Join(outputDir, "route_map.md"),
		MermaidPath:  filepath.Join(outputDir, "route_map.mmd"),
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化 route manifest 失败: %w", err)
	}
	if err := os.WriteFile(artifacts.ManifestPath, manifestData, 0644); err != nil {
		return nil, fmt.Errorf("写入 route manifest 失败: %w", err)
	}

	if err := os.WriteFile(artifacts.MarkdownPath, []byte(buildRouteMarkdown(manifest)), 0644); err != nil {
		return nil, fmt.Errorf("写入 route markdown 失败: %w", err)
	}

	if err := os.WriteFile(artifacts.MermaidPath, []byte(buildRouteMermaid(manifest)), 0644); err != nil {
		return nil, fmt.Errorf("写入 route mermaid 失败: %w", err)
	}

	return artifacts, nil
}

func buildRouteMarkdown(manifest *analyzer.RouteManifest) string {
	var builder strings.Builder

	builder.WriteString("# 页面与路由地图\n\n")
	builder.WriteString(fmt.Sprintf("- AppID: `%s`\n", manifest.AppID))
	builder.WriteString(fmt.Sprintf("- 配置来源: `%s`\n", manifest.ConfigSource))
	if manifest.EntryPage != "" {
		builder.WriteString(fmt.Sprintf("- 入口页: `%s`\n", manifest.EntryPage))
	}
	builder.WriteString(fmt.Sprintf("- 生成时间: `%s`\n", manifest.GeneratedAt))
	builder.WriteString("\n## 摘要\n\n")
	builder.WriteString(fmt.Sprintf("- 页面数: `%d`\n", manifest.Summary.TotalPages))
	builder.WriteString(fmt.Sprintf("- 主包页面: `%d`\n", manifest.Summary.MainPages))
	builder.WriteString(fmt.Sprintf("- 分包页面: `%d`\n", manifest.Summary.SubPackagePages))
	builder.WriteString(fmt.Sprintf("- TabBar 页面: `%d`\n", manifest.Summary.TabBarPages))
	builder.WriteString(fmt.Sprintf("- 跳转边: `%d`\n", manifest.Summary.NavigationEdgeCount))
	builder.WriteString(fmt.Sprintf("- 动态跳转边: `%d`\n", manifest.Summary.DynamicNavigationEdgeCount))
	builder.WriteString(fmt.Sprintf("- 调用链跳转边: `%d`\n", manifest.Summary.CallChainEdgeCount))
	builder.WriteString(fmt.Sprintf("- 共享路由助手: `%d`\n", manifest.Summary.SharedRouterHelperCount))
	builder.WriteString(fmt.Sprintf("- 有接口的页面: `%d`\n", manifest.Summary.PagesWithAPI))
	builder.WriteString(fmt.Sprintf("- 页面接口数: `%d`\n", manifest.Summary.APIEndpointCount))
	builder.WriteString(fmt.Sprintf("- 间接接口数: `%d`\n", manifest.Summary.IndirectAPIEndpointCount))
	builder.WriteString(fmt.Sprintf("- 引用组件数: `%d`\n", manifest.Summary.ReferencedComponents))
	if manifest.Summary.ExternalMiniProgramCount > 0 {
		builder.WriteString(fmt.Sprintf("- 外部小程序: `%d`\n", manifest.Summary.ExternalMiniProgramCount))
	}
	if manifest.Summary.OrphanPageCount > 0 {
		builder.WriteString(fmt.Sprintf("- 孤页候选: `%d`\n", manifest.Summary.OrphanPageCount))
	}

	if len(manifest.TabBar) > 0 {
		builder.WriteString("\n## TabBar\n\n")
		builder.WriteString("| 页面 | 文案 |\n")
		builder.WriteString("|------|------|\n")
		for _, item := range manifest.TabBar {
			builder.WriteString(fmt.Sprintf("| `%s` | %s |\n", item.PagePath, escapeMarkdown(item.Text)))
		}
	}

	if len(manifest.SubPackages) > 0 {
		builder.WriteString("\n## 分包\n\n")
		for _, subPackage := range manifest.SubPackages {
			builder.WriteString(fmt.Sprintf("- `%s` (%d 页)\n", subPackage.Root, subPackage.PageCount))
		}
	}

	builder.WriteString("\n## 页面清单\n")
	for _, page := range manifest.Pages {
		builder.WriteString(fmt.Sprintf("\n### `%s`\n\n", page.Route))
		builder.WriteString(fmt.Sprintf("- 包类型: `%s`\n", page.PackageType))
		if page.PackageRoot != "" {
			builder.WriteString(fmt.Sprintf("- 分包根目录: `%s`\n", page.PackageRoot))
		}
		if page.Title != "" {
			builder.WriteString(fmt.Sprintf("- 标题: `%s`\n", page.Title))
		}
		if page.IsEntry {
			builder.WriteString("- 入口页: `true`\n")
		}
		if page.IsTabBar {
			builder.WriteString("- TabBar: `true`\n")
		}
		builder.WriteString(fmt.Sprintf("- 文件: `%s` `%s` `%s` `%s`\n",
			emptyAsDash(page.Files.JS),
			emptyAsDash(page.Files.WXML),
			emptyAsDash(page.Files.WXSS),
			emptyAsDash(page.Files.JSON),
		))

		if len(page.UsingComponents) > 0 {
			builder.WriteString("- 组件:\n")
			for _, component := range page.UsingComponents {
				builder.WriteString(fmt.Sprintf("  - `%s`\n", component))
			}
		}

		if len(page.Dependencies) > 0 {
			builder.WriteString("- 依赖模块:\n")
			for _, dependency := range page.Dependencies {
				builder.WriteString(fmt.Sprintf("  - `%s`\n", dependency))
			}
		}

		if len(page.APIUsage) > 0 {
			builder.WriteString("- 接口:\n")
			for _, endpoint := range page.APIUsage {
				if endpoint.SourceKind == "indirect" && endpoint.ViaModule != "" {
					builder.WriteString(fmt.Sprintf("  - `[间接] %s %s` via `%s` (%s:%d)\n",
						endpoint.Method, endpoint.RawURL, endpoint.ViaModule, endpoint.FilePath, endpoint.LineNumber))
					continue
				}
				builder.WriteString(fmt.Sprintf("  - `%s %s` (%s:%d)\n",
					endpoint.Method, endpoint.RawURL, endpoint.FilePath, endpoint.LineNumber))
			}
		}

		outEdges := collectOutgoingEdges(manifest.NavigationEdges, page.Route)
		if len(outEdges) > 0 {
			builder.WriteString("- 跳转:\n")
			for _, edge := range outEdges {
				target := edge.TargetPage
				if target == "" {
					target = "[dynamic]"
				}
				meta := make([]string, 0, 4)
				if edge.HandlerName != "" {
					meta = append(meta, "handler="+edge.HandlerName)
				}
				if edge.TriggerEvent != "" {
					meta = append(meta, "event="+edge.TriggerEvent)
				}
				if edge.TriggerText != "" {
					meta = append(meta, "text="+edge.TriggerText)
				}
				if edge.Dynamic {
					meta = append(meta, "dynamic")
				}
				metaText := ""
				if len(meta) > 0 {
					metaText = " [" + escapeMarkdown(strings.Join(meta, ", ")) + "]"
				}
				builder.WriteString(fmt.Sprintf("  - `%s -> %s` via `%s` raw=`%s`%s (%s:%d)\n",
					edge.SourcePage, target, edge.Method, edge.RawTarget, metaText, edge.SourceFile, edge.LineNumber))
				if len(edge.CallChain) > 0 {
					builder.WriteString(fmt.Sprintf("    - 链路: `%s`\n", escapeMarkdown(formatCallChain(edge.CallChain))))
				}
			}
		}
	}

	if len(manifest.SharedRouterHelpers) > 0 {
		builder.WriteString("\n## 共享路由助手\n\n")
		builder.WriteString("| 文件 | 函数 | 使用页面 | 方法 | 目标线索 |\n")
		builder.WriteString("|------|------|----------|------|----------|\n")
		for _, helper := range manifest.SharedRouterHelpers {
			builder.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s | %s |\n",
				helper.FilePath,
				helper.FunctionName,
				escapeMarkdown(strings.Join(helper.UsedByPages, "<br/>")),
				escapeMarkdown(strings.Join(helper.Methods, ", ")),
				escapeMarkdown(strings.Join(helper.TargetHints, "<br/>")),
			))
		}
	}

	if len(manifest.ExternalMiniPrograms) > 0 {
		builder.WriteString("\n## 外部小程序\n\n")
		for _, appID := range manifest.ExternalMiniPrograms {
			builder.WriteString(fmt.Sprintf("- `%s`\n", appID))
		}
	}

	if len(manifest.OrphanPages) > 0 {
		builder.WriteString("\n## 孤页候选\n\n")
		for _, route := range manifest.OrphanPages {
			builder.WriteString(fmt.Sprintf("- `%s`\n", route))
		}
	}

	builder.WriteString("\n## Mermaid\n\n")
	builder.WriteString("请配合 `route_map.mmd` 查看图结构。\n")

	return builder.String()
}

func buildRouteMermaid(manifest *analyzer.RouteManifest) string {
	var builder strings.Builder

	builder.WriteString("graph TD\n")
	for _, page := range manifest.Pages {
		builder.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", mermaidNodeID(page.Route), escapeMermaid(page.Route)))
	}
	for _, edge := range manifest.NavigationEdges {
		targetID := mermaidNodeID(edge.TargetPage)
		targetLabel := edge.TargetPage
		if edge.TargetPage == "" {
			targetID = mermaidDynamicNodeID(edge)
			targetLabel = "[dynamic] " + edge.RawTarget
			builder.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", targetID, escapeMermaid(targetLabel)))
		}
		link := "-->"
		if edge.Dynamic {
			link = "-.->"
		}
		labelParts := []string{edge.Method}
		if edge.HandlerName != "" {
			labelParts = append(labelParts, edge.HandlerName)
		}
		if helper := lastSharedHelperName(edge.CallChain); helper != "" {
			labelParts = append(labelParts, "via "+helper)
		}
		if edge.TriggerText != "" {
			labelParts = append(labelParts, edge.TriggerText)
		}
		builder.WriteString(fmt.Sprintf("  %s %s|%s| %s\n",
			mermaidNodeID(edge.SourcePage),
			link,
			escapeMermaid(strings.Join(labelParts, " / ")),
			targetID,
		))
	}

	if len(manifest.OrphanPages) > 0 {
		for _, route := range manifest.OrphanPages {
			builder.WriteString(fmt.Sprintf("  %s[\"%s (orphan)\"]\n", mermaidNodeID(route), escapeMermaid(route)))
		}
	}

	return builder.String()
}

func collectOutgoingEdges(edges []analyzer.NavigationEdge, route string) []analyzer.NavigationEdge {
	results := make([]analyzer.NavigationEdge, 0)
	for _, edge := range edges {
		if edge.SourcePage == route {
			results = append(results, edge)
		}
	}
	return results
}

func emptyAsDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func escapeMarkdown(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "\n", " ")
	return replacer.Replace(value)
}

func escapeMermaid(value string) string {
	replacer := strings.NewReplacer("\"", "'", "\n", " ")
	return replacer.Replace(value)
}

func mermaidNodeID(route string) string {
	normalized := regexp.MustCompile(`[^a-zA-Z0-9]+`).ReplaceAllString(route, "_")
	normalized = strings.Trim(normalized, "_")
	if normalized == "" {
		return "route_node"
	}
	return "route_" + normalized
}

func mermaidDynamicNodeID(edge analyzer.NavigationEdge) string {
	seed := edge.SourcePage + "_" + edge.Method + "_" + edge.RawTarget + "_" + edge.HandlerName
	normalized := regexp.MustCompile(`[^a-zA-Z0-9]+`).ReplaceAllString(seed, "_")
	normalized = strings.Trim(normalized, "_")
	if normalized == "" {
		return "route_dynamic"
	}
	return "route_dynamic_" + normalized
}

func formatCallChain(chain []analyzer.CallChainStep) string {
	parts := make([]string, 0, len(chain))
	for _, step := range chain {
		label := step.FilePath + ":" + step.FunctionName
		if step.LineNumber > 0 {
			label = fmt.Sprintf("%s:%d", label, step.LineNumber)
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, " -> ")
}

func lastSharedHelperName(chain []analyzer.CallChainStep) string {
	for index := len(chain) - 1; index >= 0; index-- {
		if chain[index].Kind == "shared_helper" {
			return chain[index].FunctionName
		}
	}
	return ""
}
