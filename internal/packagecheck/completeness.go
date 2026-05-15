package packagecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	StatusFull    = "full"
	StatusPartial = "partial"
	StatusUnknown = "unknown"

	reportDirName = ".gwxapkg"
	jsonFileName  = "package_completeness.json"
	mdFileName    = "package_completeness.md"
)

type Report struct {
	AppID                   string             `json:"appid,omitempty"`
	GeneratedAt             string             `json:"generated_at"`
	SourceDir               string             `json:"source_dir"`
	Status                  string             `json:"status"`
	DeclaredSubpackageCount int                `json:"declared_subpackages"`
	FoundSubpackageCount    int                `json:"found_subpackages"`
	MissingSubpackageCount  int                `json:"missing_subpackages"`
	DeclaredPageCount       int                `json:"declared_pages"`
	RealPageCount           int                `json:"real_pages"`
	PlaceholderPageCount    int                `json:"placeholder_pages"`
	MissingPageCount        int                `json:"missing_pages"`
	PackageFiles            []PackageFile      `json:"package_files"`
	MissingSubpackages      []string           `json:"missing_subpackage_roots,omitempty"`
	PlaceholderPages        []string           `json:"placeholder_page_routes,omitempty"`
	MissingPages            []string           `json:"missing_page_routes,omitempty"`
	Subpackages             []SubpackageReport `json:"subpackages"`
	JSONPath                string             `json:"json_path,omitempty"`
	MarkdownPath            string             `json:"markdown_path,omitempty"`
	Notes                   []string           `json:"notes,omitempty"`
}

type PackageFile struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Root string `json:"root,omitempty"`
	Main bool   `json:"main,omitempty"`
}

type SubpackageReport struct {
	Root             string   `json:"root"`
	PageCount        int      `json:"page_count"`
	RealPages        int      `json:"real_pages"`
	PlaceholderPages int      `json:"placeholder_pages"`
	MissingPages     int      `json:"missing_pages"`
	Found            bool     `json:"found"`
	PackageFiles     []string `json:"package_files,omitempty"`
}

type appConfig struct {
	Pages       []string     `json:"pages"`
	SubPackages []subPackage `json:"subPackages"`
	Subpackages []subPackage `json:"subpackages"`
}

type subPackage struct {
	Root  string   `json:"root"`
	Pages []string `json:"pages"`
}

func AnalyzeAndWrite(rootDir, appID string, packageFiles []string) (*Report, error) {
	report, err := Analyze(rootDir, appID, packageFiles)
	if err != nil {
		return nil, err
	}
	if report.Status == StatusUnknown {
		return report, nil
	}
	if err := WriteReport(rootDir, report); err != nil {
		return report, err
	}
	return report, nil
}

func Analyze(rootDir, appID string, packageFiles []string) (*Report, error) {
	rootDir = filepath.Clean(rootDir)
	report := &Report{
		AppID:       appID,
		GeneratedAt: time.Now().Format(time.RFC3339),
		SourceDir:   rootDir,
		Status:      StatusUnknown,
	}

	configPath := filepath.Join(rootDir, "app.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		report.Notes = append(report.Notes, "未找到 app.json，无法判断分包完整性")
		return report, nil
	}

	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析 app.json 失败: %w", err)
	}

	subpackages := normalizeSubpackages(cfg)
	packageFileReports, packageRoots := classifyPackageFiles(packageFiles, subpackages)
	report.PackageFiles = packageFileReports

	report.DeclaredPageCount = len(cfg.Pages)
	for _, route := range cfg.Pages {
		report.addPageState(classifyPage(rootDir, route))
	}

	for _, sub := range subpackages {
		report.DeclaredPageCount += len(sub.Pages)
		subReport := SubpackageReport{
			Root:      sub.Root,
			PageCount: len(sub.Pages),
		}
		for _, page := range sub.Pages {
			route := joinRoute(sub.Root, page)
			state := classifyPage(rootDir, route)
			report.addPageState(state)
			switch state.Kind {
			case pageReal:
				subReport.RealPages++
			case pagePlaceholder:
				subReport.PlaceholderPages++
			case pageMissing:
				subReport.MissingPages++
			}
		}

		if files := packageRoots[sub.Root]; len(files) > 0 {
			subReport.Found = true
			subReport.PackageFiles = append(subReport.PackageFiles, files...)
			sort.Strings(subReport.PackageFiles)
		}
		if subReport.RealPages > 0 {
			subReport.Found = true
		}
		if !subReport.Found && subReport.PageCount > 0 {
			report.MissingSubpackages = append(report.MissingSubpackages, sub.Root)
		}
		report.Subpackages = append(report.Subpackages, subReport)
	}

	report.DeclaredSubpackageCount = len(subpackages)
	for _, sub := range report.Subpackages {
		if sub.Found {
			report.FoundSubpackageCount++
		}
	}
	report.MissingSubpackageCount = len(report.MissingSubpackages)

	if report.MissingSubpackageCount == 0 && report.PlaceholderPageCount == 0 && report.MissingPageCount == 0 {
		report.Status = StatusFull
	} else {
		report.Status = StatusPartial
		report.Notes = append(report.Notes, "当前输出目录包含完整路由骨架，但缺失分包下的占位页面不代表真实源码")
	}

	sort.Strings(report.MissingSubpackages)
	sort.Strings(report.PlaceholderPages)
	sort.Strings(report.MissingPages)
	sort.Slice(report.Subpackages, func(i, j int) bool {
		return report.Subpackages[i].Root < report.Subpackages[j].Root
	})

	return report, nil
}

func WriteReport(rootDir string, report *Report) error {
	reportDir := filepath.Join(rootDir, reportDirName)
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return err
	}

	jsonPath := filepath.Join(reportDir, jsonFileName)
	mdPath := filepath.Join(reportDir, mdFileName)
	report.JSONPath = filepath.ToSlash(filepath.Join(reportDirName, jsonFileName))
	report.MarkdownPath = filepath.ToSlash(filepath.Join(reportDirName, mdFileName))

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		return err
	}
	return os.WriteFile(mdPath, []byte(renderMarkdown(report)), 0644)
}

func ReadReport(rootDir string) (*Report, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, reportDirName, jsonFileName))
	if err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

func (r *Report) IsPartial() bool {
	return r != nil && r.Status == StatusPartial
}

func (r *Report) IsFull() bool {
	return r != nil && r.Status == StatusFull
}

func normalizeSubpackages(cfg appConfig) []subPackage {
	seen := make(map[string]int)
	result := make([]subPackage, 0, len(cfg.SubPackages)+len(cfg.Subpackages))
	for _, sub := range append(cfg.SubPackages, cfg.Subpackages...) {
		root := normalizeRouteRoot(sub.Root)
		if root == "" {
			continue
		}
		pages := normalizePages(sub.Pages)
		if index, ok := seen[root]; ok {
			result[index].Pages = mergePages(result[index].Pages, pages)
			continue
		}
		seen[root] = len(result)
		result = append(result, subPackage{Root: root, Pages: pages})
	}
	return result
}

func normalizePages(pages []string) []string {
	seen := make(map[string]struct{}, len(pages))
	result := make([]string, 0, len(pages))
	for _, page := range pages {
		page = strings.Trim(strings.TrimSpace(filepath.ToSlash(page)), "/")
		page = strings.TrimSuffix(page, ".html")
		page = strings.TrimSuffix(page, ".wxml")
		page = strings.TrimSuffix(page, ".js")
		if page == "" {
			continue
		}
		if _, ok := seen[page]; ok {
			continue
		}
		seen[page] = struct{}{}
		result = append(result, page)
	}
	sort.Strings(result)
	return result
}

func mergePages(left, right []string) []string {
	return normalizePages(append(append([]string{}, left...), right...))
}

func normalizeRouteRoot(root string) string {
	root = strings.Trim(strings.TrimSpace(filepath.ToSlash(root)), "/")
	return strings.TrimSuffix(root, "/")
}

func joinRoute(root, page string) string {
	root = normalizeRouteRoot(root)
	page = strings.Trim(strings.TrimSpace(filepath.ToSlash(page)), "/")
	if root == "" {
		return page
	}
	return root + "/" + page
}

type pageKind string

const (
	pageReal        pageKind = "real"
	pagePlaceholder pageKind = "placeholder"
	pageMissing     pageKind = "missing"
)

type pageState struct {
	Route string
	Kind  pageKind
}

func classifyPage(rootDir, route string) pageState {
	route = strings.Trim(strings.TrimSpace(filepath.ToSlash(route)), "/")
	jsPath := filepath.Join(rootDir, filepath.FromSlash(route+".js"))
	wxmlPath := filepath.Join(rootDir, filepath.FromSlash(route+".wxml"))

	jsExists, jsPlaceholder := filePlaceholderState(jsPath, placeholderJS(route))
	wxmlExists, wxmlPlaceholder := filePlaceholderState(wxmlPath, placeholderWXML(route))

	switch {
	case !jsExists && !wxmlExists:
		return pageState{Route: route, Kind: pageMissing}
	case jsPlaceholder || wxmlPlaceholder:
		return pageState{Route: route, Kind: pagePlaceholder}
	default:
		return pageState{Route: route, Kind: pageReal}
	}
}

func filePlaceholderState(path string, placeholder string) (bool, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	return true, strings.TrimSpace(string(data)) == strings.TrimSpace(placeholder)
}

func placeholderJS(route string) string {
	return "// " + route + ".js\nPage({data: {}})"
}

func placeholderWXML(route string) string {
	return "<!--" + route + ".wxml--><text>" + route + ".wxml</text>"
}

func (r *Report) addPageState(state pageState) {
	switch state.Kind {
	case pageReal:
		r.RealPageCount++
	case pagePlaceholder:
		r.PlaceholderPageCount++
		r.PlaceholderPages = append(r.PlaceholderPages, state.Route)
	case pageMissing:
		r.MissingPageCount++
		r.MissingPages = append(r.MissingPages, state.Route)
	}
}

func classifyPackageFiles(files []string, subpackages []subPackage) ([]PackageFile, map[string][]string) {
	rootsByToken := make(map[string]string, len(subpackages))
	for _, sub := range subpackages {
		rootsByToken[packageRootToken(sub.Root)] = sub.Root
	}

	results := make([]PackageFile, 0, len(files))
	roots := make(map[string][]string)
	for _, file := range files {
		if strings.TrimSpace(file) == "" {
			continue
		}
		name := filepath.Base(file)
		item := PackageFile{
			Path: filepath.ToSlash(file),
			Name: name,
		}
		token := packageFileToken(name)
		if strings.EqualFold(token, "__APP__") || strings.EqualFold(name, "__APP__.wxapkg") {
			item.Main = true
		} else if root, ok := rootsByToken[token]; ok {
			item.Root = root
			roots[root] = append(roots[root], item.Path)
		} else {
			item.Root = inferRootFromPackageFile(name)
			if item.Root != "" {
				roots[item.Root] = append(roots[item.Root], item.Path)
			}
		}
		results = append(results, item)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Main != results[j].Main {
			return results[i].Main
		}
		return results[i].Name < results[j].Name
	})
	for root := range roots {
		sort.Strings(roots[root])
	}
	return results, roots
}

func packageRootToken(root string) string {
	root = normalizeRouteRoot(root)
	return strings.Trim(strings.ReplaceAll(root, "/", "_"), "_")
}

func packageFileToken(name string) string {
	name = strings.TrimSuffix(name, filepath.Ext(name))
	return strings.Trim(name, "_")
}

func inferRootFromPackageFile(name string) string {
	token := packageFileToken(name)
	if token == "" || token == "__APP__" || strings.Contains(token, "PLUGINCODE") {
		return ""
	}
	return strings.ReplaceAll(token, "_", "/")
}

func renderMarkdown(report *Report) string {
	var b strings.Builder
	b.WriteString("# 小程序分包完整性报告\n\n")
	b.WriteString(fmt.Sprintf("- AppID: `%s`\n", report.AppID))
	b.WriteString(fmt.Sprintf("- 状态: `%s`\n", report.Status))
	b.WriteString(fmt.Sprintf("- 声明分包: `%d`\n", report.DeclaredSubpackageCount))
	b.WriteString(fmt.Sprintf("- 已找到分包: `%d`\n", report.FoundSubpackageCount))
	b.WriteString(fmt.Sprintf("- 缺失分包: `%d`\n", report.MissingSubpackageCount))
	b.WriteString(fmt.Sprintf("- 页面: `%d` 声明 / `%d` 真实 / `%d` 占位 / `%d` 缺失\n\n",
		report.DeclaredPageCount,
		report.RealPageCount,
		report.PlaceholderPageCount,
		report.MissingPageCount,
	))

	if len(report.Notes) > 0 {
		b.WriteString("## 说明\n\n")
		for _, note := range report.Notes {
			b.WriteString("- " + note + "\n")
		}
		b.WriteString("\n")
	}

	if len(report.MissingSubpackages) > 0 {
		b.WriteString("## 缺失分包\n\n")
		for _, root := range report.MissingSubpackages {
			b.WriteString("- `" + root + "`\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## 分包明细\n\n")
	b.WriteString("| Root | 页面数 | 真实 | 占位 | 缺失 | 状态 |\n")
	b.WriteString("|---|---:|---:|---:|---:|---|\n")
	for _, sub := range report.Subpackages {
		status := "缺失"
		if sub.Found {
			status = "已找到"
		}
		b.WriteString(fmt.Sprintf("| `%s` | %d | %d | %d | %d | %s |\n",
			sub.Root,
			sub.PageCount,
			sub.RealPages,
			sub.PlaceholderPages,
			sub.MissingPages,
			status,
		))
	}

	if len(report.PlaceholderPages) > 0 {
		b.WriteString("\n## 占位页面\n\n")
		for _, route := range report.PlaceholderPages {
			b.WriteString("- `" + route + "`\n")
		}
	}

	return b.String()
}
