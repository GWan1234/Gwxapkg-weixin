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
	"sync"

	"github.com/25smoking/Gwxapkg/internal/config"
	"github.com/dop251/goja"
)

type XmlParser struct {
	OutputDir string
	// 解析器版本
	Version string
}

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

func collectHTMLWXMLGenerateCalls(outputDir string, option config.WxapkgInfo, gwx map[string]interface{}) {
	seen := make(map[string]bool)
	for _, rawName := range option.RawFiles {
		normalized := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rawName)), "/")
		if !strings.HasSuffix(strings.ToLower(normalized), ".html") {
			continue
		}
		for _, candidate := range htmlSourceCandidates(outputDir, option.SourcePath, normalized) {
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			code, err := os.ReadFile(candidate)
			if err != nil {
				continue
			}
			collectDirectWXMLGenerateCalls(string(code), gwx)
		}
	}
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
			sb.WriteString("__wxAppCode__[")
			sb.WriteString(strconv.Quote(alias))
			sb.WriteString("]=")
			sb.WriteString(gencode)
			sb.WriteByte('\n')
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
	for value.ExportType().Kind() == reflect.Func {
		fn, ok := goja.AssertFunction(value)
		if !ok {
			return nil, fmt.Errorf("expected function, got %T", value.Export())
		}

		var err error
		value, err = fn(goja.Undefined(), args...)
		if err != nil {
			return nil, err
		}
		args = nil
	}
	return value, nil
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

func getXml(path string, scriptCode, gencode string, results chan<- map[string]string, wg *sync.WaitGroup, version string, sem chan struct{}) {
	defer wg.Done()

	// 限制并发数
	sem <- struct{}{}
	// 释放信号量
	defer func() { <-sem }()

	if shouldUseTaroStaticFallback(path, scriptCode) {
		results <- map[string]string{path: buildTaroStaticWXML(path, scriptCode)}
		return
	}

	// 提取函数名和参数
	funcName, params := extractFuncNameAndArgs(gencode)
	if funcName == "" {
		log.Printf("Error extracting function name and arguments from gencode: %s\n", gencode)
		return
	}

	vm := goja.New()

	// 包裹 try...catch 语句以捕获 JavaScript 错误
	safeScript := `
	try {
		` + scriptCode + `
	} catch (e) {
		//console.error(e);
	}
	`

	// 定义 console 对象
	console := vm.NewObject()
	_ = console.Set("log", func(call goja.FunctionCall) goja.Value {
		// 使用 call.Arguments 获取传递给 console.log 的参数
		args := call.Arguments
		for _, arg := range args {
			fmt.Println(arg.String())
		}
		return goja.Undefined()
	})
	_ = console.Set("error", func(call goja.FunctionCall) goja.Value {
		args := call.Arguments
		for _, arg := range args {
			fmt.Println("ERROR:", arg.String())
		}
		return goja.Undefined()
	})
	_ = console.Set("warn", func(call goja.FunctionCall) goja.Value {
		args := call.Arguments
		for _, arg := range args {
			fmt.Println("WARN:", arg.String())
		}
		return goja.Undefined()
	})
	_ = vm.Set("console", console)

	// 运行脚本代码，定义所有函数
	_, err := vm.RunString(safeScript)
	if err != nil {
		var gojaErr *goja.Exception
		if errors.As(err, &gojaErr) {
			log.Println("JavaScript error:", gojaErr.String())
		} else {
			log.Println("Error running script:", err)
		}
		return
	}

	// 获取函数对象
	fn, ok := goja.AssertFunction(vm.Get(funcName))
	if !ok {
		log.Printf("Error asserting function for %s\n", funcName)
		return
	}

	// 准备参数列表
	args := make([]goja.Value, len(params))
	for i, param := range params {
		args[i] = vm.ToValue(param)
	}

	// 调用函数并获取结果
	result, err := fn(goja.Undefined(), args...)
	if err != nil {
		log.Printf("Error calling function: %v\n", err)
		return
	}

	// 递归调用函数直到获得非函数结果
	finalResult, err := getFinalResult(vm, result)
	if err != nil {
		log.Printf("Error getting final result: %v\n", err)
		return
	}

	bestContent := getDomTree(finalResult.Export())
	for _, args := range wxmlRenderArgVariants(vm) {
		candidate, err := getFinalResultWithArgs(vm, result, args...)
		if err != nil {
			continue
		}
		content := getDomTree(candidate.Export())
		if len(strings.TrimSpace(content)) > len(strings.TrimSpace(bestContent)) {
			bestContent = content
		}
	}
	if strings.TrimSpace(bestContent) == "" {
		for _, args := range wxmlListRenderArgVariants(vm) {
			candidate, err := getFinalResultWithArgs(vm, result, args...)
			if err != nil {
				continue
			}
			content := getDomTree(candidate.Export())
			if len(strings.TrimSpace(content)) > len(strings.TrimSpace(bestContent)) {
				bestContent = content
			}
		}
	}
	if strings.TrimSpace(bestContent) == "" && shouldUseTaroStaticFallback(path, scriptCode) {
		bestContent = buildTaroStaticWXML(path, scriptCode)
	}

	// 保存结果
	results <- map[string]string{path: bestContent}
}

func (p *XmlParser) Parse(option config.WxapkgInfo) error {
	saveDir := p.OutputDir

	var frameFile = option.Option.ViewSource
	// 存放生成函数代码
	var gwx = make(map[string]interface{})
	results := make(chan map[string]string)
	var wg sync.WaitGroup

	// 最大并发数
	const maxConcurrent = 5
	sem := make(chan struct{}, maxConcurrent)

	code, err := os.ReadFile(frameFile)
	if err != nil {
		log.Printf("Error reading file: %v\n", err)
		return err
	}

	codeStr := string(code)
	scriptCode := codeStr

	// 防止报错
	patch := `var noCss=true;var window={};var navigator={};navigator.userAgent="iPhone";window.screen={};
document={getElementsByTagName:()=>{}};function define(){};function require(){};
var setCssToHead=function(file,_xcInvalid,info){return ()=>{}};`

	// 如果是 html 文件，提取 script 代码
	if strings.HasSuffix(frameFile, ".html") {
		scriptCode = matchScripts(codeStr)
	}

	scriptCode = strings.Replace(scriptCode, "var setCssToHead =", "var setCssToHead2 =", -1)
	scriptCode = strings.Replace(scriptCode, "var noCss", "var noCss2", -1)
	// 如果是子包
	if isSubpackage(&option) {
		scriptCode = strings.Replace(scriptCode, "$gwx('init', global);", "", 1)
	}

	// 正则匹配生成函数
	getFuc(scriptCode, gwx)
	collectHTMLWXMLGenerateCalls(p.OutputDir, option, gwx)

	scriptCode = patch + scriptCode + buildWXMLModuleRegistrationScript(gwx)

	// 运行生成函数
	for path, gencode := range gwx {
		wg.Add(1)
		go getXml(path, scriptCode, gencode.(string), results, &wg, p.Version, sem)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	finalResults := make(map[string]string)
	for result := range results {
		for k, v := range result {
			finalResults[k] = v
		}
	}

	for name, content := range finalResults {
		name = filepath.Join(saveDir, name)
		_ = save(name, []byte(content))
	}

	return nil
}
