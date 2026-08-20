package unpack

import (
	"errors"
	"fmt"
	"log"
	"os"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/internal/config"
	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

type XmlParser struct {
	OutputDir string
	// 解析器版本
	Version string
}

const (
	wxmlRenderCallTimeout  = 500 * time.Millisecond
	wxmlBatchRenderTimeout = 3 * time.Second
)

const wxmlRenderTimeoutCause = "WXML 生成函数执行超时"

// 获取生成函数
func getFuc(code string, gwx map[string]interface{}) {
	re := regexp.MustCompile(`(?:else\s+)?__wxAppCode__\[\s*['"]([^'"]+\.wxml)['"]\s*\]\s*=\s*(\$[A-Za-z_$][\w$]*\s*\(\s*['"][^'"]+\.wxml['"]\s*\)\s*;)`)

	matches := re.FindAllStringSubmatch(code, -1)
	if len(matches) > 0 {
		for _, match := range matches {
			gwx[match[1]] = match[2]
		}
	}
}

func collectDirectWXMLGenerateCalls(code string, gwx map[string]interface{}) {
	re := regexp.MustCompile(`(?:var\s+[A-Za-z_$][\w$]*\s*=\s*)?(\$[A-Za-z_$][\w$]*\s*\(\s*['"]([^'"]+\.wxml)['"]\s*\)\s*;)`)

	matches := re.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		if _, exists := gwx[match[2]]; exists {
			continue
		}
		gwx[match[2]] = match[1]
	}
}

var wxmlFunctionDefinitionRe = regexp.MustCompile(`(?m)(?:var\s+)?\$[A-Za-z_$][\w$]*\s*=\s*function\b|function\s+\$[A-Za-z_$][\w$]*\s*\(`)

func hasWXMLFunctionDefinition(code string) bool {
	return wxmlFunctionDefinitionRe.MatchString(code)
}

// extractWXMLFunctionDefinitions 从 HTML wrapper 中仅保留 $gwx 声明。
// wrapper 往往混有 getApp()/wx API/WXSS 注入等真实运行时副作用；反编译只需
// 函数定义本身，完整执行会让无关副作用中断后续模板登记。
func extractWXMLFunctionDefinitions(source string) string {
	program, err := parser.ParseFile(nil, "", source, parser.IgnoreRegExpErrors, parser.WithDisableSourceMaps)
	if err != nil || program == nil {
		return ""
	}

	var definitions []string
	for _, declaration := range program.DeclarationList {
		for _, binding := range declaration.List {
			identifier, ok := binding.Target.(*ast.Identifier)
			if !ok || binding.Initializer == nil || !strings.HasPrefix(identifier.Name.String(), "$") {
				continue
			}
			initializer := sourceForNode(source, binding.Initializer)
			if initializer != "" {
				definitions = append(definitions, "var "+identifier.Name.String()+" = "+initializer+";")
			}
		}
	}
	for _, statement := range program.Body {
		declaration, ok := statement.(*ast.FunctionDeclaration)
		if !ok || declaration.Function == nil || declaration.Function.Name == nil || !strings.HasPrefix(declaration.Function.Name.Name.String(), "$") {
			continue
		}
		if definition := sourceForNode(source, declaration); definition != "" {
			definitions = append(definitions, definition)
		}
	}
	return strings.Join(definitions, "\n")
}

func collectHTMLWXMLGenerateCalls(outputDir string, option config.WxapkgInfo, gwx map[string]interface{}) {
	_ = collectAdditionalWXMLScripts(outputDir, option, "", gwx)
}

// collectAdditionalWXMLScripts 收集分包 HTML wrapper 及其实际脚本。
// 旧实现只提取了 $gwx*_XC_* 调用，却丢掉定义这些函数的脚本，
// 最终就会出现 "Error asserting function" 并缺失 WXML。
func collectAdditionalWXMLScripts(outputDir string, option config.WxapkgInfo, frameFile string, gwx map[string]interface{}) []string {
	seen := make(map[string]bool)
	frameFile = cleanComparablePath(frameFile)
	scripts := make([]string, 0)
	for _, rawName := range option.RawFiles {
		normalized := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rawName)), "/")
		if !strings.HasSuffix(strings.ToLower(normalized), ".html") {
			continue
		}
		for _, candidate := range htmlSourceCandidates(outputDir, option.SourcePath, normalized) {
			comparable := cleanComparablePath(candidate)
			if comparable == frameFile || seen[comparable] {
				continue
			}
			seen[comparable] = true
			code, err := os.ReadFile(candidate)
			if err != nil {
				continue
			}
			scriptCode := matchScripts(string(code))
			getFuc(scriptCode, gwx)
			collectDirectWXMLGenerateCalls(scriptCode, gwx)
			// 大多数 HTML 只是通知运行时执行 __wxAppCode__[...wxss]，并不
			// 包含生成函数；把它们放进 VM 会触发无意义的 WXSS 副作用。
			// 仅执行真正携带 $gwx 定义的 wrapper，调用语句仍会被上面收集。
			if hasWXMLFunctionDefinition(scriptCode) {
				if definitions := extractWXMLFunctionDefinitions(scriptCode); definitions != "" {
					scripts = append(scripts, definitions)
				}
			}
			break
		}
	}
	return scripts
}

// collectWXMLRuntimeBootstrap 为采用新版 CodeSpace/WCC 运行时的分包补齐主包
// 运行时。新版分包的 page-frame.js 只调用 batchAddCompiledTemplate，运行时
// 本体位于主包的 app-wxss.js；若分包单独执行，就会出现 __wxCodeSpace__ 未定义。
func collectWXMLRuntimeBootstrap(outputDir, frameFile string) []string {
	bootstrap := filepath.Join(outputDir, "app-wxss.js")
	if cleanComparablePath(bootstrap) == cleanComparablePath(frameFile) {
		return nil
	}
	code, err := os.ReadFile(bootstrap)
	if err != nil || !strings.Contains(string(code), "__wxCodeSpace__") {
		return nil
	}
	return []string{string(code)}
}

// collectAdditionalWXMLRuntimeScripts 收集当前包内由 CodeSpace 分块加载的
// WebView 脚本。它们不是 HTML wrapper，因此不能复用旧的 HTML 扫描逻辑。
func collectAdditionalWXMLRuntimeScripts(outputDir string, option config.WxapkgInfo, frameFile string) []string {
	seen := map[string]bool{cleanComparablePath(frameFile): true}
	scripts := make([]string, 0)

	appendScript := func(candidate string) {
		comparable := cleanComparablePath(candidate)
		if comparable == "" || seen[comparable] {
			return
		}
		code, err := os.ReadFile(candidate)
		if err != nil {
			return
		}
		content := string(code)
		// batchAddCompiledScripts 可能携带整段页面运行时代码；WXML 还原只
		// 需要模板登记，执行前者会触发 Page/getApp 等业务副作用。
		if !strings.Contains(content, "__wxCodeSpace__.batchAddCompiledTemplate") {
			return
		}
		seen[comparable] = true
		scripts = append(scripts, content)
	}

	for _, rawName := range option.RawFiles {
		normalized := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rawName)), "/")
		if !strings.HasSuffix(strings.ToLower(normalized), ".js") {
			continue
		}
		for _, candidate := range htmlSourceCandidates(outputDir, option.SourcePath, normalized) {
			before := len(scripts)
			appendScript(candidate)
			if len(scripts) != before {
				break
			}
		}
	}

	return scripts
}

func cleanComparablePath(filename string) string {
	if strings.TrimSpace(filename) == "" {
		return ""
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return filepath.Clean(filename)
	}
	return filepath.Clean(abs)
}

func htmlSourceCandidates(outputDir, sourcePath, rel string) []string {
	candidates := []string{
		filepath.Join(outputDir, filepath.FromSlash(rel)),
		filepath.Join(sourcePath, filepath.FromSlash(rel)),
	}

	if sourcePath != "" {
		sourceSlash := filepath.ToSlash(sourcePath)
		if strings.HasSuffix(sourceSlash, strings.TrimSuffix(pathpkg.Dir(rel), ".")) {
			candidates = append(candidates, filepath.Join(sourcePath, filepath.Base(rel)))
		}
	}

	seen := make(map[string]bool, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		result = append(result, candidate)
	}
	return result
}

// 提取函数名和参数
func extractFuncNameAndArgs(gencode string) (string, []interface{}) {
	re := regexp.MustCompile(`(\$[A-Za-z_$][\w$]*)\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	matches := re.FindStringSubmatch(gencode)
	if len(matches) < 3 {
		return "", nil
	}

	funcName := matches[1]
	arg := matches[2]

	return funcName, []interface{}{arg}
}

func wxmlModuleAliases(name string) []string {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return nil
	}

	withoutPrefix := strings.TrimPrefix(normalized, "./")
	cleaned := pathpkg.Clean(withoutPrefix)
	if cleaned == "." {
		cleaned = withoutPrefix
	}
	cleaned = strings.TrimPrefix(cleaned, "/")

	candidates := []string{normalized}
	if cleaned != "" {
		candidates = append(candidates, cleaned, "./"+cleaned)
	}

	seen := make(map[string]bool, len(candidates))
	aliases := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		aliases = append(aliases, candidate)
	}
	return aliases
}

func buildWXMLModuleRegistrationScript(gwx map[string]interface{}) string {
	if len(gwx) == 0 {
		return ""
	}

	keys := make([]string, 0, len(gwx))
	for name := range gwx {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("\n;(function(){\n")
	sb.WriteString("if (typeof __wxAppCode__ === 'undefined') { __wxAppCode__ = {}; }\n")
	for _, name := range keys {
		gencode, ok := gwx[name].(string)
		if !ok {
			continue
		}
		gencode = strings.TrimSpace(gencode)
		if gencode == "" {
			continue
		}
		if !strings.HasSuffix(gencode, ";") {
			gencode += ";"
		}
		for _, alias := range wxmlModuleAliases(name) {
			sb.WriteString("try{")
			sb.WriteString("__wxAppCode__[")
			sb.WriteString(strconv.Quote(alias))
			sb.WriteString("]=")
			sb.WriteString(gencode)
			sb.WriteString("}catch(_gwxRegisterError){}\n")
		}
	}
	sb.WriteString("})();\n")
	return sb.String()
}

func shouldUseTaroStaticFallback(path, scriptCode string) bool {
	cleaned := cleanWXMLPath(path)
	if cleaned == "" || !strings.HasSuffix(cleaned, ".wxml") {
		return false
	}
	return strings.Contains(scriptCode, "taro_tmpl")
}

func cleanWXMLPath(name string) string {
	normalized := strings.TrimSpace(filepath.ToSlash(name))
	normalized = strings.TrimPrefix(normalized, "./")
	normalized = strings.TrimPrefix(normalized, "/")
	cleaned := pathpkg.Clean(normalized)
	if cleaned == "." {
		return normalized
	}
	return strings.TrimPrefix(cleaned, "/")
}

func buildTaroStaticWXML(path, scriptCode string) string {
	cleaned := cleanWXMLPath(path)
	if cleaned == "" {
		return ""
	}
	if cleaned == "base.wxml" {
		return buildTaroBaseWXML(scriptCode)
	}

	return fmt.Sprintf("<!--%s-->\n<import src=\"%s\" />\n<template is=\"taro_tmpl\" data=\"{{root:root}}\" />\n",
		cleaned,
		relativeBaseWXMLPath(cleaned),
	)
}

func relativeBaseWXMLPath(cleanedPath string) string {
	dir := pathpkg.Dir(cleanedPath)
	if dir == "." || dir == "" {
		return "base.wxml"
	}
	depth := strings.Count(dir, "/") + 1
	return strings.Repeat("../", depth) + "base.wxml"
}

func buildTaroBaseWXML(scriptCode string) string {
	templateNames := extractTaroBaseTemplateNames(scriptCode)

	var sb strings.Builder
	sb.WriteString("<!--base.wxml-->\n")
	sb.WriteString("<template name=\"taro_tmpl\">\n")
	sb.WriteString("\t<block wx:for=\"{{root.cn || root.children || []}}\" wx:for-item=\"item\" wx:for-index=\"index\" wx:key=\"sid\">\n")
	sb.WriteString("\t\t<template is=\"{{'tmpl_0_' + (item.nn || item.tag || 'undefined')}}\" data=\"{{item:item,index:index,sid:item.sid}}\" />\n")
	sb.WriteString("\t</block>\n")
	sb.WriteString("</template>\n")

	for _, name := range templateNames {
		if name == "taro_tmpl" {
			continue
		}
		sb.WriteString("<template name=\"")
		sb.WriteString(name)
		sb.WriteString("\">\n\t<block />\n</template>\n")
	}
	return sb.String()
}

func extractTaroBaseTemplateNames(scriptCode string) []string {
	re := regexp.MustCompile(`d_\[x\[0\]\]\["([^"]+)"\]\s*=\s*function`)
	matches := re.FindAllStringSubmatch(scriptCode, -1)

	seen := map[string]bool{
		"taro_tmpl":        true,
		"tmpl_0_undefined": true,
	}
	names := []string{"taro_tmpl", "tmpl_0_undefined"}
	validName := regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
	for _, match := range matches {
		if len(match) < 2 || seen[match[1]] || !validName.MatchString(match[1]) {
			continue
		}
		seen[match[1]] = true
		names = append(names, match[1])
	}
	sort.Strings(names)
	return names
}

// 递归调用函数直到获得非函数结果
func getFinalResult(vm *goja.Runtime, value goja.Value) (goja.Value, error) {
	return getFinalResultWithArgs(vm, value)
}

func getFinalResultWithArgs(vm *goja.Runtime, value goja.Value, args ...goja.Value) (goja.Value, error) {
	// goja.Value 可能为 nil（typed nil interface 包装后也需防御）
	for {
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return value, nil
		}
		exportType := value.ExportType()
		if exportType == nil || exportType.Kind() != reflect.Func {
			break
		}
		fn, ok := goja.AssertFunction(value)
		if !ok {
			return nil, fmt.Errorf("expected function, got %T", value.Export())
		}

		var err error
		value, err = callWXMLFunction(vm, fn, goja.Undefined(), args...)
		if err != nil {
			return nil, err
		}
		args = nil
	}
	return value, nil
}

// callWXMLFunction 为不可信的 WXML 生成函数设置时间上限。部分新版包的
// 模板函数会在模拟上下文中无限递归或无限循环；没有中断机制时整个 CLI 会
// 停在“还原工程结构”。Interrupt 可从计时器 goroutine 安全调用。
func callWXMLFunction(vm *goja.Runtime, fn goja.Callable, this goja.Value, args ...goja.Value) (goja.Value, error) {
	timerFinished := make(chan struct{})
	timer := time.AfterFunc(wxmlRenderCallTimeout, func() {
		vm.Interrupt(wxmlRenderTimeoutCause)
		close(timerFinished)
	})
	value, err := fn(this, args...)
	if !timer.Stop() {
		// 若定时器已触发，必须等中断写入完成后再清除，避免污染下一次调用。
		<-timerFinished
		vm.ClearInterrupt()
	}
	return value, err
}

func isWXMLRenderTimeout(err error) bool {
	var interrupted *goja.InterruptedError
	return errors.As(err, &interrupted) && interrupted.Value() == wxmlRenderTimeoutCause
}

func mockWXMLData(vm *goja.Runtime, overrides map[string]bool) goja.Value {
	obj := vm.NewObject()
	for ch := 'a'; ch <= 'z'; ch++ {
		_ = obj.Set(string(ch), true)
	}
	for ch := 'A'; ch <= 'Z'; ch++ {
		_ = obj.Set(string(ch), true)
	}
	_ = obj.Set("d", vm.NewObject())
	_ = obj.Set("length", 1)

	for key, value := range overrides {
		_ = obj.Set(key, value)
	}

	return obj
}

func wxmlRenderArgVariants(vm *goja.Runtime) [][]goja.Value {
	return [][]goja.Value{
		{
			mockWXMLData(vm, map[string]bool{"c": false, "f": false}),
			vm.NewObject(),
			vm.NewObject(),
		},
		{
			mockWXMLData(vm, nil),
			vm.NewObject(),
			vm.NewObject(),
		},
	}
}

func mockWXMLListData(vm *goja.Runtime) goja.Value {
	obj := vm.NewObject()
	item := vm.NewObject()
	for _, key := range []string{"a", "b", "c", "d", "e", "f", "id", "name", "type", "time", "address"} {
		_ = item.Set(key, key)
	}
	list := vm.NewArray(item)

	for ch := 'a'; ch <= 'z'; ch++ {
		_ = obj.Set(string(ch), list)
	}
	for ch := 'A'; ch <= 'Z'; ch++ {
		_ = obj.Set(string(ch), list)
	}
	_ = obj.Set("d", vm.NewObject())
	_ = obj.Set("length", 1)

	return obj
}

func wxmlListRenderArgVariants(vm *goja.Runtime) [][]goja.Value {
	return [][]goja.Value{
		{
			mockWXMLListData(vm),
			vm.NewObject(),
			vm.NewObject(),
		},
	}
}

// 生成视图代码
func getDomTree(node interface{}) string {
	// 用于构建 XML 字符串的函数
	var processNodes func(node map[string]interface{}, indentLevel int, isRoot bool) string
	processNodes = func(node map[string]interface{}, indentLevel int, isRoot bool) string {
		var sb strings.Builder

		// 生成缩进
		indent := strings.Repeat("\t", indentLevel)

		// 获取标签名称
		tag, ok := node["tag"].(string)
		if !ok {
			return ""
		}
		tag = strings.TrimPrefix(tag, "wx-") // 去除前缀 wx-
		isVirtual := tag == "virtual"

		// 如果是根节点或虚拟节点，不添加开始标签
		if !isRoot && !isVirtual {
			// 开始标签
			sb.WriteString(indent)
			sb.WriteString("<")
			sb.WriteString(tag)

			// 处理属性
			if attr, ok := node["attr"].(map[string]interface{}); ok {
				for key, value := range attr {
					key = strings.TrimPrefix(key, "$wxs:")
					if strings.HasPrefix(key, "$") {
						continue
					}
					if value == nil {
						sb.WriteString(fmt.Sprintf(" %s=\"\"", key))
					} else {
						sb.WriteString(fmt.Sprintf(" %s=\"%v\"", key, value))
					}
				}
			}

			// 结束标签
			sb.WriteString(">")
		}

		// 处理子节点
		if children, ok := node["children"].([]interface{}); ok {
			if len(children) > 0 && !isRoot && !isVirtual {
				sb.WriteString("\n")
			}
			for _, child := range children {
				if childMap, ok := child.(map[string]interface{}); ok {
					childIndent := indentLevel + 1
					if isRoot || isVirtual {
						childIndent = indentLevel
					}
					sb.WriteString(processNodes(childMap, childIndent, false))
				} else {
					// 如果 children 是字符串且字符串为空，则不换行
					if str, ok := child.(string); ok {
						if str != "" {
							textIndent := indentLevel + 1
							if isRoot || isVirtual {
								textIndent = indentLevel
							}
							sb.WriteString(strings.Repeat("\t", textIndent))
							sb.WriteString(str + "\n")
						}
					}
				}
			}
		}

		// 结束标签（如果不是根节点或虚拟节点）
		if !isRoot && !isVirtual {
			sb.WriteString(indent)
			sb.WriteString("</")
			sb.WriteString(tag)
			sb.WriteString(">\n")
		}

		return sb.String()
	}

	// 将根节点转换为 map
	rootNode, ok := node.(map[string]interface{})
	if !ok {
		return ""
	}

	// 生成并返回最终的 XML 字符串，不包括根标签
	return processNodes(rootNode, 0, true)
}

const wxmlRuntimePatch = `
var noCss=true;
var window={};
var navigator={userAgent:"iPhone"};
window.screen={};
var document={getElementsByTagName:function(){return []}};
var global={};
var __wxAppCode__={};
var __wxConfig={};
var __wxConfig__={};
// WXML 初始化可能只做 wx API 的能力探测；反编译不应执行真实 API。
// 用可链式访问的惰性对象承接 wx.getAccountInfoSync().miniProgram.appId 等调用。
var __gwxRuntimeStub=(function(){var stub=function(){return stub;};return typeof Proxy==="function"?new Proxy(stub,{get:function(){return stub;},apply:function(){return stub;}}):stub;}());
var wx=typeof Proxy==="function"?new Proxy({}, {get:function(){return __gwxRuntimeStub;}}):{};
__wxConfig=typeof Proxy==="function"?new Proxy({accountInfo:{appId:""}}, {get:function(target,key){return key in target?target[key]:__gwxRuntimeStub;}}):__wxConfig;
function App(){}
function Page(){}
function getApp(){return {globalData:{appId:""}};}
function define(){}
function require(){return {}}
var setCssToHead=function(){return function(){}};
`

type wxmlBatchReport struct {
	ScriptErrors []string
	Failures     []string
}

// wxmlRuntimeTemplate 是新版 CodeSpace 运行时登记到 __wxAppCode__ 中的模板。
// 它已经是可调用值，不再是旧版 $gwx('path') 形式的生成语句。
type wxmlRuntimeTemplate struct {
	value goja.Value
}

func prepareWXMLScript(scriptCode string, subpackage bool) string {
	scriptCode = strings.ReplaceAll(scriptCode, "var setCssToHead =", "var setCssToHead2 =")
	scriptCode = strings.ReplaceAll(scriptCode, "var noCss", "var noCss2")
	if subpackage {
		scriptCode = strings.Replace(scriptCode, "$gwx('init', global);", "", 1)
	}
	return scriptCode
}

func newWXMLRuntime() (*goja.Runtime, error) {
	vm := goja.New()
	console := vm.NewObject()
	noop := func(goja.FunctionCall) goja.Value { return goja.Undefined() }
	_ = console.Set("log", noop)
	_ = console.Set("error", noop)
	_ = console.Set("warn", noop)
	_ = console.Set("info", noop)
	_ = vm.Set("console", console)
	if _, err := vm.RunString(wxmlRuntimePatch); err != nil {
		return nil, err
	}
	return vm, nil
}

func sourceForNode(source string, node ast.Node) string {
	if node == nil {
		return ""
	}
	start := int(node.Idx0()) - 1
	end := int(node.Idx1()) - 1
	if start < 0 || end <= start || end > len(source) {
		return ""
	}
	return source[start:end]
}

func requiredWXMLFunctions(gwx map[string]interface{}) map[string]struct{} {
	required := make(map[string]struct{})
	for _, rawCode := range gwx {
		gencode, ok := rawCode.(string)
		if !ok {
			continue
		}
		name, _ := extractFuncNameAndArgs(gencode)
		if name != "" {
			required[name] = struct{}{}
		}
	}
	return required
}

// recoverMissingWXMLFunctions 从 AST 中单独恢复尚未载入的 $gwx*_XC_* 函数。
// 某个编译包在顶层初始化时抛异常，会使后方的 var/function 声明来不及执行；
// 用 AST 精确取出目标声明，比用正则截取嵌套函数更稳定。
func recoverMissingWXMLFunctions(vm *goja.Runtime, scriptSources []string, gwx map[string]interface{}, subpackage bool) []string {
	required := requiredWXMLFunctions(gwx)
	for name := range required {
		if _, ok := goja.AssertFunction(vm.Get(name)); ok {
			delete(required, name)
		}
	}
	if len(required) == 0 {
		return nil
	}

	var recoveryErrors []string
	for sourceIndex, source := range scriptSources {
		prepared := prepareWXMLScript(source, subpackage)
		program, parseErr := parser.ParseFile(nil, "", prepared, parser.IgnoreRegExpErrors, parser.WithDisableSourceMaps)
		if parseErr != nil || program == nil {
			if parseErr != nil {
				recoveryErrors = append(recoveryErrors, fmt.Sprintf("script[%d] AST: %v", sourceIndex, parseErr))
			}
			continue
		}

		for _, declaration := range program.DeclarationList {
			for _, binding := range declaration.List {
				identifier, ok := binding.Target.(*ast.Identifier)
				if !ok || binding.Initializer == nil {
					continue
				}
				name := identifier.Name.String()
				if _, needed := required[name]; !needed {
					continue
				}
				initializer := sourceForNode(prepared, binding.Initializer)
				if initializer == "" {
					continue
				}
				if _, runErr := vm.RunString("var " + name + " = " + initializer + ";"); runErr != nil {
					recoveryErrors = append(recoveryErrors, fmt.Sprintf("%s: %v", name, runErr))
					continue
				}
				if _, ok := goja.AssertFunction(vm.Get(name)); ok {
					delete(required, name)
				}
			}
		}

		for _, statement := range program.Body {
			declaration, ok := statement.(*ast.FunctionDeclaration)
			if !ok || declaration.Function == nil || declaration.Function.Name == nil {
				continue
			}
			name := declaration.Function.Name.Name.String()
			if _, needed := required[name]; !needed {
				continue
			}
			definition := sourceForNode(prepared, declaration)
			if definition == "" {
				continue
			}
			if _, runErr := vm.RunString(definition); runErr != nil {
				recoveryErrors = append(recoveryErrors, fmt.Sprintf("%s: %v", name, runErr))
				continue
			}
			if _, ok := goja.AssertFunction(vm.Get(name)); ok {
				delete(required, name)
			}
		}

		if len(required) == 0 {
			break
		}
	}
	return recoveryErrors
}

// loadWXMLRuntime 在同一个 VM 中分段载入主包与分包视图脚本。
// 每段单独捕获错误，一个 wrapper 异常不会阻止后续函数定义。
func loadWXMLRuntime(scriptSources []string, gwx map[string]interface{}, subpackage bool) (*goja.Runtime, []string, error) {
	vm, err := newWXMLRuntime()
	if err != nil {
		return nil, nil, err
	}

	var scriptErrors []string
	for index, source := range scriptSources {
		prepared := prepareWXMLScript(source, subpackage)
		// 由 Go 运行时捕获每段异常并继续下一段。不在 JavaScript 中再包一层
		// try 块，否则新版引擎会把块内 function 声明限定在局部作用域。
		if _, runErr := vm.RunString(prepared); runErr != nil {
			scriptErrors = append(scriptErrors, fmt.Sprintf("script[%d]: %v", index, runErr))
		}
	}
	scriptErrors = append(scriptErrors, recoverMissingWXMLFunctions(vm, scriptSources, gwx, subpackage)...)

	if registration := buildWXMLModuleRegistrationScript(gwx); registration != "" {
		if _, runErr := vm.RunString(registration); runErr != nil {
			scriptErrors = append(scriptErrors, fmt.Sprintf("module registration: %v", runErr))
		}
	}
	return vm, scriptErrors, nil
}

// collectRuntimeWXMLTemplates 从新版 WCC 运行时收集真正登记的 WXML 模板。
// 旧版直接从源码中提取 $gwx 调用；新版则在 batchAddCompiledTemplate 执行后才
// 写入 __wxAppCode__，因此必须在同一 VM 中读取。
func collectRuntimeWXMLTemplates(vm *goja.Runtime, gwx map[string]interface{}) {
	appCode := vm.Get("__wxAppCode__")
	if appCode == nil || goja.IsUndefined(appCode) || goja.IsNull(appCode) {
		return
	}
	obj := appCode.ToObject(vm)
	if obj == nil {
		return
	}

	for _, rawPath := range obj.Keys() {
		if !strings.HasSuffix(strings.ToLower(rawPath), ".wxml") {
			continue
		}
		value := obj.Get(rawPath)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			continue
		}

		canonicalPath := strings.TrimPrefix(filepath.ToSlash(rawPath), "./")
		replaced := false
		for existingPath := range gwx {
			if strings.TrimPrefix(filepath.ToSlash(existingPath), "./") == canonicalPath {
				gwx[existingPath] = wxmlRuntimeTemplate{value: value}
				replaced = true
			}
		}
		if !replaced {
			gwx[canonicalPath] = wxmlRuntimeTemplate{value: value}
		}
	}
}

func renderWXMLResult(vm *goja.Runtime, result goja.Value, funcName string) (string, error) {
	finalResult, err := getFinalResult(vm, result)
	if err != nil {
		return "", fmt.Errorf("解析 %s 返回值失败: %w", funcName, err)
	}
	if finalResult == nil || goja.IsUndefined(finalResult) || goja.IsNull(finalResult) {
		return "", fmt.Errorf("生成函数 %s 返回空值", funcName)
	}

	bestContent := getDomTree(finalResult.Export())
	for _, variantArgs := range wxmlRenderArgVariants(vm) {
		candidate, candidateErr := getFinalResultWithArgs(vm, result, variantArgs...)
		if isWXMLRenderTimeout(candidateErr) {
			return "", fmt.Errorf("解析 %s 返回值失败: %w", funcName, candidateErr)
		}
		if candidateErr != nil || candidate == nil {
			continue
		}
		content := getDomTree(candidate.Export())
		if len(strings.TrimSpace(content)) > len(strings.TrimSpace(bestContent)) {
			bestContent = content
		}
	}
	if strings.TrimSpace(bestContent) == "" {
		for _, variantArgs := range wxmlListRenderArgVariants(vm) {
			candidate, candidateErr := getFinalResultWithArgs(vm, result, variantArgs...)
			if isWXMLRenderTimeout(candidateErr) {
				return "", fmt.Errorf("解析 %s 返回值失败: %w", funcName, candidateErr)
			}
			if candidateErr != nil || candidate == nil {
				continue
			}
			content := getDomTree(candidate.Export())
			if len(strings.TrimSpace(content)) > len(strings.TrimSpace(bestContent)) {
				bestContent = content
			}
		}
	}
	if strings.TrimSpace(bestContent) == "" {
		return "", fmt.Errorf("生成函数 %s 未产生可用 DOM", funcName)
	}
	return bestContent, nil
}

func renderWXMLModule(vm *goja.Runtime, path string, rawCode interface{}, fallbackScript string) (string, error) {
	if shouldUseTaroStaticFallback(path, fallbackScript) {
		return buildTaroStaticWXML(path, fallbackScript), nil
	}
	if runtimeTemplate, ok := rawCode.(wxmlRuntimeTemplate); ok {
		return renderWXMLResult(vm, runtimeTemplate.value, "CodeSpace 模板 "+path)
	}

	gencode, ok := rawCode.(string)
	if !ok {
		return "", fmt.Errorf("生成语句无效")
	}

	funcName, params := extractFuncNameAndArgs(gencode)
	if funcName == "" {
		return "", fmt.Errorf("无法从生成语句提取函数: %s", gencode)
	}

	fn, ok := goja.AssertFunction(vm.Get(funcName))
	if !ok {
		return "", fmt.Errorf("未载入生成函数 %s", funcName)
	}

	args := make([]goja.Value, len(params))
	for i, param := range params {
		args[i] = vm.ToValue(param)
	}
	result, err := callWXMLFunction(vm, fn, goja.Undefined(), args...)
	if err != nil {
		return "", fmt.Errorf("调用 %s 失败: %w", funcName, err)
	}
	return renderWXMLResult(vm, result, funcName)
}

func renderWXMLBatch(scriptSources []string, gwx map[string]interface{}, subpackage bool) (map[string]string, wxmlBatchReport, error) {
	results := make(map[string]string, len(gwx))
	report := wxmlBatchReport{}
	fallbackScript := ""
	for _, source := range scriptSources {
		if strings.Contains(source, "taro_tmpl") {
			fallbackScript = source
			break
		}
	}

	// Taro 统一模板可直接静态还原，无需初始化庞大的视图运行时。
	if fallbackScript != "" {
		for path := range gwx {
			if shouldUseTaroStaticFallback(path, fallbackScript) {
				results[path] = buildTaroStaticWXML(path, fallbackScript)
			}
		}
		if len(results) == len(gwx) {
			return results, report, nil
		}
	}

	vm, scriptErrors, err := loadWXMLRuntime(scriptSources, gwx, subpackage)
	if err != nil {
		return nil, report, err
	}
	report.ScriptErrors = scriptErrors
	collectRuntimeWXMLTemplates(vm, gwx)

	paths := make([]string, 0, len(gwx))
	for path := range gwx {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	deadline := time.Now().Add(wxmlBatchRenderTimeout)
	for _, path := range paths {
		if time.Now().After(deadline) {
			report.Failures = append(report.Failures, fmt.Sprintf("%s: WXML 批量还原时间预算耗尽", path))
			continue
		}
		rawCode := gwx[path]
		if gencode, ok := rawCode.(string); ok && strings.TrimSpace(gencode) == "" {
			report.Failures = append(report.Failures, fmt.Sprintf("%s: 生成语句无效", path))
			continue
		}
		content, renderErr := renderWXMLModule(vm, path, rawCode, fallbackScript)
		if renderErr != nil {
			report.Failures = append(report.Failures, fmt.Sprintf("%s: %v", path, renderErr))
			continue
		}
		results[path] = content
	}
	return results, report, nil
}

func logWXMLBatchReport(report wxmlBatchReport) {
	if len(report.ScriptErrors) > 0 {
		log.Printf("WXML 视图脚本部分加载失败: %d 段（示例: %s）\n", len(report.ScriptErrors), report.ScriptErrors[0])
	}
	if len(report.Failures) == 0 {
		return
	}
	examples := report.Failures
	if len(examples) > 3 {
		examples = examples[:3]
	}
	log.Printf("WXML 还原跳过 %d 个页面（示例: %s）\n", len(report.Failures), strings.Join(examples, "; "))
}

func (p *XmlParser) Parse(option config.WxapkgInfo) error {
	saveDir := p.OutputDir

	var frameFile = option.Option.ViewSource
	// 存放生成函数代码
	var gwx = make(map[string]interface{})
	code, err := os.ReadFile(frameFile)
	if err != nil {
		log.Printf("Error reading file: %v\n", err)
		return err
	}

	codeStr := string(code)
	scriptCode := codeStr

	// 如果是 html 文件，提取 script 代码
	if strings.HasSuffix(frameFile, ".html") {
		scriptCode = matchScripts(codeStr)
	}

	// 正则匹配生成函数
	getFuc(scriptCode, gwx)
	collectDirectWXMLGenerateCalls(scriptCode, gwx)
	// 新版分包需要先加载主包的 CodeSpace/WCC 运行时，随后再登记当前包模板。
	scriptSources := collectWXMLRuntimeBootstrap(p.OutputDir, frameFile)
	scriptSources = append(scriptSources, scriptCode)
	scriptSources = append(scriptSources, collectAdditionalWXMLScripts(p.OutputDir, option, frameFile, gwx)...)
	scriptSources = append(scriptSources, collectAdditionalWXMLRuntimeScripts(p.OutputDir, option, frameFile)...)

	finalResults, report, err := renderWXMLBatch(scriptSources, gwx, isSubpackage(&option))
	if err != nil {
		return fmt.Errorf("WXML 运行时初始化失败: %w", err)
	}
	logWXMLBatchReport(report)

	names := make([]string, 0, len(finalResults))
	for name := range finalResults {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := finalResults[name]
		name = filepath.Join(saveDir, name)
		if err := save(name, []byte(content)); err != nil {
			return err
		}
	}

	return nil
}
