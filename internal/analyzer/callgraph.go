package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxCallTraceDepth = 6
	hintSeedKey       = "__route_target__"
)

type routeAnalyzerContext struct {
	rootDir     string
	pageScripts map[string]bool
	moduleCache map[string]*jsModuleInfo
}

type jsModuleInfo struct {
	RelPath       string
	Text          string
	Functions     map[string]*jsFunction
	ModuleAliases map[string]string
	NamedImports  map[string]jsImportBinding
	ExportAliases map[string]string
}

type jsFunction struct {
	Name       string
	Start      int
	End        int
	Body       string
	Params     []string
	LineNumber int
}

type jsImportBinding struct {
	ModulePath string
	ExportName string
}

type routeValueHint struct {
	Raw     string
	Dynamic bool
}

type navigationTrace struct {
	Method     string
	TargetPage string
	RawTarget  string
	Dynamic    bool
	SourceFile string
	LineNumber int
	CallChain  []CallChainStep
}

type jsCall struct {
	Callee     string
	Args       []string
	LineNumber int
}

type jsFunctionPattern struct {
	pattern        *regexp.Regexp
	nameGroup      int
	paramsGroup    int
	paramsAltGroup int
	allowReserved  bool
}

type sharedRouterHelperAccumulator struct {
	filePath     string
	functionName string
	pages        map[string]bool
	methods      map[string]bool
	targets      map[string]bool
	dynamic      bool
}

var (
	functionPatternMethodFunc   = regexp.MustCompile(`(?m)(?:^|[,{]\s*)([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?function\s*\(([^\n)]*)\)\s*\{`)
	functionPatternMethodArrow  = regexp.MustCompile(`(?m)(?:^|[,{]\s*)([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?\(([^\n)]*)\)\s*=>\s*\{`)
	functionPatternMethodShort  = regexp.MustCompile(`(?m)^\s*([A-Za-z_$][\w$]*)\s*\(([^\n)]*)\)\s*\{`)
	functionPatternFunctionDecl = regexp.MustCompile(`(?m)\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{`)
	functionPatternVarFunc      = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{`)
	functionPatternVarArrow     = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*\{`)
	functionPatternExportFunc   = regexp.MustCompile(`(?m)\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{`)
	functionPatternExportArrow  = regexp.MustCompile(`(?m)\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*\{`)

	requireAssignPattern       = regexp.MustCompile("(?m)\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\(\\s*[\"'`]" + "([^\"'`]+)" + "[\"'`]\\s*\\)")
	requireDestructPattern     = regexp.MustCompile("(?ms)\\b(?:const|let|var)\\s*\\{\\s*([^}]+)\\s*\\}\\s*=\\s*require\\(\\s*[\"'`]" + "([^\"'`]+)" + "[\"'`]\\s*\\)")
	importDefaultPattern       = regexp.MustCompile("(?m)\\bimport\\s+([A-Za-z_$][\\w$]*)\\s*(?:,\\s*\\{[^}]*\\})?\\s+from\\s+[\"'`]" + "([^\"'`]+)" + "[\"'`]")
	importNamedPattern         = regexp.MustCompile("(?ms)\\bimport\\s+(?:[A-Za-z_$][\\w$]*\\s*,\\s*)?\\{\\s*([^}]+)\\s*\\}\\s*from\\s*[\"'`]" + "([^\"'`]+)" + "[\"'`]")
	exportDirectPattern        = regexp.MustCompile(`(?m)\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\b`)
	exportNamedBlockPattern    = regexp.MustCompile(`(?ms)\bexport\s*\{\s*([^}]+)\s*\}`)
	exportFunctionNamePattern  = regexp.MustCompile(`(?m)\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(`)
	exportVariableNamePattern  = regexp.MustCompile(`(?m)\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b`)
	moduleExportsAssignPattern = regexp.MustCompile(`(?m)\b(?:module\.)?exports\s*=\s*\{`)

	callExprPattern = regexp.MustCompile(`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,2})\s*\(`)
)

func newRouteAnalyzerContext(rootDir string) *routeAnalyzerContext {
	return &routeAnalyzerContext{
		rootDir:     rootDir,
		pageScripts: make(map[string]bool),
		moduleCache: make(map[string]*jsModuleInfo),
	}
}

func (ctx *routeAnalyzerContext) markPageScript(jsPath string) {
	if jsPath == "" {
		return
	}
	ctx.pageScripts[jsPath] = true
}

func (ctx *routeAnalyzerContext) loadModule(relPath string) *jsModuleInfo {
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return nil
	}
	if cached, ok := ctx.moduleCache[relPath]; ok {
		return cached
	}

	data, err := os.ReadFile(filepath.Join(ctx.rootDir, filepath.FromSlash(relPath)))
	if err != nil {
		ctx.moduleCache[relPath] = nil
		return nil
	}

	text := string(data)
	moduleAliases, namedImports := extractJSImportBindings(ctx.rootDir, relPath, text)
	info := &jsModuleInfo{
		RelPath:       relPath,
		Text:          text,
		Functions:     extractJSFunctions(text),
		ModuleAliases: moduleAliases,
		NamedImports:  namedImports,
		ExportAliases: extractJSExportAliases(text),
	}
	ctx.moduleCache[relPath] = info
	return info
}

func extractJSImportBindings(rootDir, fromJSPath, text string) (map[string]string, map[string]jsImportBinding) {
	moduleAliases := make(map[string]string)
	namedImports := make(map[string]jsImportBinding)

	for _, match := range requireAssignPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		resolved := resolveJSImport(rootDir, fromJSPath, match[2])
		if resolved == "" {
			continue
		}
		moduleAliases[strings.TrimSpace(match[1])] = resolved
	}

	for _, match := range requireDestructPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		resolved := resolveJSImport(rootDir, fromJSPath, match[2])
		if resolved == "" {
			continue
		}
		for localName, exportName := range parseJSImportBindings(match[1]) {
			namedImports[localName] = jsImportBinding{
				ModulePath: resolved,
				ExportName: exportName,
			}
		}
	}

	for _, match := range importDefaultPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		resolved := resolveJSImport(rootDir, fromJSPath, match[2])
		if resolved == "" {
			continue
		}
		moduleAliases[strings.TrimSpace(match[1])] = resolved
	}

	for _, match := range importNamedPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		resolved := resolveJSImport(rootDir, fromJSPath, match[2])
		if resolved == "" {
			continue
		}
		for localName, exportName := range parseJSImportBindings(match[1]) {
			namedImports[localName] = jsImportBinding{
				ModulePath: resolved,
				ExportName: exportName,
			}
		}
	}

	return moduleAliases, namedImports
}

func parseJSImportBindings(raw string) map[string]string {
	results := make(map[string]string)
	for _, part := range splitTopLevel(raw, ',') {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}

		exportName := item
		localName := item
		if strings.Contains(item, " as ") {
			pieces := strings.SplitN(item, " as ", 2)
			exportName = strings.TrimSpace(pieces[0])
			localName = strings.TrimSpace(pieces[1])
		} else if strings.Contains(item, ":") {
			pieces := strings.SplitN(item, ":", 2)
			exportName = strings.TrimSpace(pieces[0])
			localName = strings.TrimSpace(pieces[1])
		}

		exportName = normalizeJSIdentifier(exportName)
		localName = normalizeJSIdentifier(localName)
		if exportName == "" || localName == "" {
			continue
		}
		results[localName] = exportName
	}
	return results
}

func extractJSFunctions(text string) map[string]*jsFunction {
	results := make(map[string]*jsFunction)
	seen := make(map[string]bool)
	patterns := []jsFunctionPattern{
		{pattern: functionPatternMethodFunc, nameGroup: 1, paramsGroup: 2},
		{pattern: functionPatternMethodArrow, nameGroup: 1, paramsGroup: 2},
		{pattern: functionPatternMethodShort, nameGroup: 1, paramsGroup: 2},
		{pattern: functionPatternFunctionDecl, nameGroup: 1, paramsGroup: 2},
		{pattern: functionPatternVarFunc, nameGroup: 1, paramsGroup: 2},
		{pattern: functionPatternVarArrow, nameGroup: 1, paramsGroup: 2, paramsAltGroup: 3},
		{pattern: functionPatternExportFunc, nameGroup: 1, paramsGroup: 2},
		{pattern: functionPatternExportArrow, nameGroup: 1, paramsGroup: 2, paramsAltGroup: 3},
	}

	for _, descriptor := range patterns {
		for _, match := range descriptor.pattern.FindAllStringSubmatchIndex(text, -1) {
			name := submatchValue(text, match, descriptor.nameGroup)
			if name == "" || (!descriptor.allowReserved && isReservedJSName(name)) {
				continue
			}

			params := submatchValue(text, match, descriptor.paramsGroup)
			if params == "" && descriptor.paramsAltGroup > 0 {
				params = submatchValue(text, match, descriptor.paramsAltGroup)
			}

			openBraceOffset := strings.LastIndex(text[match[0]:match[1]], "{")
			if openBraceOffset < 0 {
				continue
			}
			openBrace := match[0] + openBraceOffset
			closeBrace := findMatchingBrace(text, openBrace)
			if closeBrace <= openBrace {
				continue
			}

			key := fmt.Sprintf("%s:%d:%d", name, openBrace, closeBrace)
			if seen[key] {
				continue
			}
			seen[key] = true

			function := &jsFunction{
				Name:       name,
				Start:      match[0],
				End:        closeBrace,
				Body:       text[openBrace : closeBrace+1],
				Params:     parseJSParams(params),
				LineNumber: lineNumberAtOffset(text, match[0]),
			}
			if existing, ok := results[name]; !ok || function.Start < existing.Start {
				results[name] = function
			}
		}
	}

	return results
}

func submatchValue(text string, match []int, group int) string {
	idx := group * 2
	if idx+1 >= len(match) || match[idx] < 0 || match[idx+1] < 0 {
		return ""
	}
	return strings.TrimSpace(text[match[idx]:match[idx+1]])
}

func parseJSParams(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	results := make([]string, 0)
	for _, part := range splitTopLevel(raw, ',') {
		param := normalizeJSIdentifier(strings.TrimSpace(part))
		if param == "" {
			continue
		}
		results = append(results, param)
	}
	return results
}

func extractJSExportAliases(text string) map[string]string {
	results := make(map[string]string)

	for _, match := range exportDirectPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		exportName := normalizeJSIdentifier(match[1])
		targetName := normalizeJSIdentifier(match[2])
		if exportName == "" || targetName == "" {
			continue
		}
		results[exportName] = targetName
	}

	for _, match := range exportNamedBlockPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		for _, part := range splitTopLevel(match[1], ',') {
			item := strings.TrimSpace(part)
			if item == "" {
				continue
			}
			localName := item
			exportName := item
			if strings.Contains(item, " as ") {
				pieces := strings.SplitN(item, " as ", 2)
				localName = strings.TrimSpace(pieces[0])
				exportName = strings.TrimSpace(pieces[1])
			}
			localName = normalizeJSIdentifier(localName)
			exportName = normalizeJSIdentifier(exportName)
			if localName == "" || exportName == "" {
				continue
			}
			results[exportName] = localName
		}
	}

	for _, match := range exportFunctionNamePattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		name := normalizeJSIdentifier(match[1])
		if name != "" {
			results[name] = name
		}
	}

	for _, match := range exportVariableNamePattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		name := normalizeJSIdentifier(match[1])
		if name != "" {
			results[name] = name
		}
	}

	for _, objectText := range extractModuleExportObjects(text) {
		for exportName, targetName := range parseModuleExportObject(objectText) {
			if exportName == "" || targetName == "" {
				continue
			}
			results[exportName] = targetName
		}
	}

	return results
}

func extractModuleExportObjects(text string) []string {
	matches := moduleExportsAssignPattern.FindAllStringIndex(text, -1)
	results := make([]string, 0, len(matches))
	for _, match := range matches {
		openBrace := strings.Index(text[match[0]:match[1]], "{")
		if openBrace < 0 {
			continue
		}
		openBrace += match[0]
		closeBrace := findMatchingBrace(text, openBrace)
		if closeBrace <= openBrace {
			continue
		}
		results = append(results, text[openBrace+1:closeBrace])
	}
	return results
}

func parseModuleExportObject(objectText string) map[string]string {
	results := make(map[string]string)
	for _, part := range splitTopLevel(objectText, ',') {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}

		colon := topLevelColonIndex(item)
		if colon < 0 {
			name := normalizeJSIdentifier(item)
			if name != "" {
				results[name] = name
			}
			continue
		}

		key := normalizeJSPropertyName(item[:colon])
		value := strings.TrimSpace(item[colon+1:])
		if key == "" || value == "" {
			continue
		}

		switch {
		case strings.HasPrefix(value, "function"), strings.HasPrefix(value, "async function"), strings.HasPrefix(value, "("), regexp.MustCompile(`^[A-Za-z_$][\w$]*\s*=>`).MatchString(value):
			results[key] = key
		default:
			target := normalizeJSIdentifier(value)
			if target == "" {
				target = key
			}
			results[key] = target
		}
	}
	return results
}

func (ctx *routeAnalyzerContext) traceFunction(route string, module *jsModuleInfo, functionName string, hints map[string]routeValueHint, depth int, visited map[string]bool) []navigationTrace {
	if module == nil || depth > maxCallTraceDepth {
		return nil
	}

	function := resolveModuleFunction(module, functionName)
	if function == nil {
		return nil
	}

	visitKey := module.RelPath + "#" + function.Name
	if visited[visitKey] {
		return nil
	}
	nextVisited := cloneVisited(visited)
	nextVisited[visitKey] = true

	localHints := cloneRouteHints(hints)
	seed := localHints[hintSeedKey]
	if seed.Raw != "" {
		for _, param := range function.Params {
			addRawTargetHints(localHints, param, seed.Raw, seed.Dynamic)
		}
	}

	results := make([]navigationTrace, 0)
	currentStep := ctx.buildCallChainStep(module.RelPath, function, depth)

	for _, trace := range extractFunctionNavigationTraces(route, module.RelPath, function, localHints) {
		trace.CallChain = prependCallChainStep(trace.CallChain, currentStep)
		results = append(results, trace)
	}

	for _, call := range extractCallExpressions(function.Body) {
		targetModule, targetFunction := ctx.resolveCallTarget(module, function, call.Callee)
		if targetModule == nil || targetFunction == "" {
			continue
		}

		callee := resolveModuleFunction(targetModule, targetFunction)
		if callee == nil {
			continue
		}

		callHints := buildCallHints(route, callee, call.Args, localHints)
		for _, trace := range ctx.traceFunction(route, targetModule, targetFunction, callHints, depth+1, nextVisited) {
			trace.CallChain = prependCallChainStep(trace.CallChain, currentStep)
			results = append(results, trace)
		}
	}

	return dedupeNavigationTraces(results)
}

func resolveModuleFunction(module *jsModuleInfo, functionName string) *jsFunction {
	if module == nil {
		return nil
	}

	functionName = normalizeJSIdentifier(functionName)
	if functionName == "" {
		return nil
	}

	if fn, ok := module.Functions[functionName]; ok {
		return fn
	}
	if mapped, ok := module.ExportAliases[functionName]; ok {
		if fn, ok := module.Functions[mapped]; ok {
			return fn
		}
	}
	return nil
}

func extractFunctionNavigationTraces(route, sourceFile string, function *jsFunction, hints map[string]routeValueHint) []navigationTrace {
	matches := jsNavigationCallStartPattern.FindAllStringSubmatchIndex(function.Body, -1)
	results := make([]navigationTrace, 0, len(matches))
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		blockStart := strings.Index(function.Body[match[0]:match[1]], "{")
		if blockStart < 0 {
			continue
		}
		blockStart += match[0]
		blockEnd := findMatchingBrace(function.Body, blockStart)
		if blockEnd <= blockStart {
			continue
		}

		method := strings.TrimSpace(function.Body[match[2]:match[3]])
		urlExpr := extractObjectPropertyExpression(function.Body[blockStart:blockEnd+1], "url")
		target, rawTarget, dynamic, ok := resolveNavigationExpressionWithHints(urlExpr, route, hints)
		if !ok {
			continue
		}

		results = append(results, navigationTrace{
			Method:     method,
			TargetPage: target,
			RawTarget:  rawTarget,
			Dynamic:    dynamic,
			SourceFile: sourceFile,
			LineNumber: function.LineNumber + lineNumberAtOffset(function.Body, match[0]) - 1,
		})
	}
	return results
}

func resolveNavigationExpressionWithHints(expr, currentRoute string, hints map[string]routeValueHint) (string, string, bool, bool) {
	if hint, ok := resolveRouteValueHint(expr, currentRoute, hints); ok {
		target, resolved := normalizeRouteReference(hint.Raw, currentRoute)
		if resolved {
			return target, hint.Raw, hint.Dynamic, true
		}
		return "", hint.Raw, true, hint.Raw != ""
	}

	return resolveNavigationExpression(expr, currentRoute)
}

func resolveRouteValueHint(expr, currentRoute string, hints map[string]routeValueHint) (routeValueHint, bool) {
	value := trimWrappingParens(strings.TrimSpace(strings.TrimSuffix(expr, ",")))
	if value == "" {
		return routeValueHint{}, false
	}

	if hint, ok := lookupRouteHint(hints, value); ok {
		return hint, true
	}

	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"') {
			return routeValueHint{Raw: value[1 : len(value)-1]}, true
		}
		if value[0] == '`' && value[len(value)-1] == '`' {
			return routeValueHint{
				Raw:     value[1 : len(value)-1],
				Dynamic: strings.Contains(value, "${"),
			}, true
		}
	}

	if literal := firstStringLiteral(value); literal != "" {
		dynamic := true
		if _, ok := normalizeRouteReference(literal, currentRoute); ok {
			return routeValueHint{Raw: literal, Dynamic: dynamic}, true
		}
		return routeValueHint{Raw: literal, Dynamic: dynamic}, true
	}

	return routeValueHint{}, false
}

func lookupRouteHint(hints map[string]routeValueHint, expr string) (routeValueHint, bool) {
	if len(hints) == 0 {
		return routeValueHint{}, false
	}

	expr = trimWrappingParens(strings.TrimSpace(expr))
	if expr == "" {
		return routeValueHint{}, false
	}

	if hint, ok := hints[expr]; ok && hint.Raw != "" {
		return hint, true
	}

	normalized := strings.Join(strings.Fields(expr), "")
	if normalized != expr {
		if hint, ok := hints[normalized]; ok && hint.Raw != "" {
			return hint, true
		}
	}

	return routeValueHint{}, false
}

func buildCallHints(route string, callee *jsFunction, args []string, baseHints map[string]routeValueHint) map[string]routeValueHint {
	results := make(map[string]routeValueHint)
	for index, param := range callee.Params {
		if index >= len(args) {
			continue
		}
		hint, ok := resolveRouteValueHint(args[index], route, baseHints)
		if !ok || hint.Raw == "" {
			continue
		}
		addRawTargetHints(results, param, hint.Raw, hint.Dynamic)
	}
	return results
}

func addRawTargetHints(hints map[string]routeValueHint, paramName, rawTarget string, dynamic bool) {
	paramName = normalizeJSIdentifier(paramName)
	rawTarget = strings.TrimSpace(rawTarget)
	if paramName == "" || rawTarget == "" {
		return
	}

	hint := routeValueHint{Raw: rawTarget, Dynamic: dynamic}
	keys := []string{
		paramName,
		paramName + ".url",
		paramName + ".route",
		paramName + ".path",
		paramName + ".page",
		paramName + ".detail.url",
		paramName + ".detail.route",
		paramName + ".detail.path",
		paramName + ".currentTarget.dataset.url",
		paramName + ".currentTarget.dataset.route",
		paramName + ".currentTarget.dataset.path",
		paramName + ".currentTarget.dataset.page",
		paramName + ".target.dataset.url",
		paramName + ".target.dataset.route",
		paramName + ".target.dataset.path",
		paramName + ".target.dataset.page",
	}
	for _, key := range keys {
		hints[key] = hint
		hints[strings.Join(strings.Fields(key), "")] = hint
	}
}

func cloneRouteHints(source map[string]routeValueHint) map[string]routeValueHint {
	if len(source) == 0 {
		return make(map[string]routeValueHint)
	}
	results := make(map[string]routeValueHint, len(source))
	for key, value := range source {
		results[key] = value
	}
	return results
}

func cloneVisited(source map[string]bool) map[string]bool {
	results := make(map[string]bool, len(source)+1)
	for key, value := range source {
		results[key] = value
	}
	return results
}

func extractCallExpressions(text string) []jsCall {
	matches := callExprPattern.FindAllStringSubmatchIndex(text, -1)
	results := make([]jsCall, 0, len(matches))
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		callee := strings.TrimSpace(text[match[2]:match[3]])
		if shouldSkipCallExpression(text, callee, match[0]) {
			continue
		}

		parenOffset := strings.Index(text[match[0]:match[1]], "(")
		if parenOffset < 0 {
			continue
		}
		openParen := match[0] + parenOffset
		closeParen := findMatchingParen(text, openParen)
		if closeParen <= openParen {
			continue
		}

		if looksLikeMethodDefinition(text, match[0], closeParen) {
			continue
		}

		argsText := text[openParen+1 : closeParen]
		results = append(results, jsCall{
			Callee:     callee,
			Args:       splitTopLevel(argsText, ','),
			LineNumber: lineNumberAtOffset(text, match[0]),
		})
	}
	return results
}

func shouldSkipCallExpression(text, callee string, start int) bool {
	switch callee {
	case "if", "for", "while", "switch", "catch", "function", "return", "typeof", "new":
		return true
	}
	if strings.HasPrefix(callee, "wx.") || strings.HasPrefix(callee, "uni.") || strings.HasPrefix(callee, "tt.") || strings.HasPrefix(callee, "my.") {
		return true
	}
	prefix := strings.TrimSpace(text[maxInt(0, start-16):start])
	return strings.HasSuffix(prefix, "function") || strings.HasSuffix(prefix, "async function")
}

func looksLikeMethodDefinition(text string, start, closeParen int) bool {
	next := nextNonWhitespaceIndex(text, closeParen+1)
	if next >= 0 && next < len(text) && text[next] == '{' {
		prev := prevNonWhitespaceIndex(text, start-1)
		if prev < 0 || text[prev] == '{' || text[prev] == ',' || text[prev] == ':' {
			return true
		}
	}
	return false
}

func findMatchingParen(text string, openParen int) int {
	if openParen < 0 || openParen >= len(text) || text[openParen] != '(' {
		return -1
	}

	depth := 0
	var quote byte
	inLineComment := false
	inBlockComment := false
	escaped := false

	for i := openParen; i < len(text); i++ {
		ch := text[i]
		next := byte(0)
		if i+1 < len(text) {
			next = text[i+1]
		}

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}

		if ch == '/' && next == '/' {
			inLineComment = true
			i++
			continue
		}
		if ch == '/' && next == '*' {
			inBlockComment = true
			i++
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			continue
		}
		if ch == '(' {
			depth++
			continue
		}
		if ch == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (ctx *routeAnalyzerContext) resolveCallTarget(module *jsModuleInfo, current *jsFunction, callee string) (*jsModuleInfo, string) {
	parts := strings.Split(strings.TrimSpace(callee), ".")
	if len(parts) == 0 {
		return nil, ""
	}

	switch len(parts) {
	case 1:
		name := normalizeJSIdentifier(parts[0])
		if name == "" || name == current.Name {
			return nil, ""
		}
		if _, ok := module.Functions[name]; ok {
			return module, name
		}
		if binding, ok := module.NamedImports[name]; ok {
			return ctx.loadModule(binding.ModulePath), binding.ExportName
		}
	case 2:
		left := normalizeJSIdentifier(parts[0])
		right := normalizeJSIdentifier(parts[1])
		switch left {
		case "this", "that", "self", "ctx", "vm":
			if right != "" && right != current.Name {
				if _, ok := module.Functions[right]; ok {
					return module, right
				}
			}
		default:
			if modulePath, ok := module.ModuleAliases[left]; ok {
				return ctx.loadModule(modulePath), right
			}
		}
	case 3:
		left := normalizeJSIdentifier(parts[0])
		middle := normalizeJSIdentifier(parts[1])
		right := normalizeJSIdentifier(parts[2])
		if middle == "default" {
			if modulePath, ok := module.ModuleAliases[left]; ok {
				return ctx.loadModule(modulePath), right
			}
		}
	}

	return nil, ""
}

func (ctx *routeAnalyzerContext) buildCallChainStep(relPath string, function *jsFunction, depth int) CallChainStep {
	kind := "shared_helper"
	if ctx.pageScripts[relPath] {
		if depth == 0 {
			kind = "page_handler"
		} else {
			kind = "page_helper"
		}
	}
	return CallChainStep{
		FilePath:     relPath,
		FunctionName: function.Name,
		Kind:         kind,
		LineNumber:   function.LineNumber,
	}
}

func prependCallChainStep(chain []CallChainStep, step CallChainStep) []CallChainStep {
	if len(chain) > 0 {
		first := chain[0]
		if first.FilePath == step.FilePath && first.FunctionName == step.FunctionName && first.Kind == step.Kind {
			return chain
		}
	}
	return append([]CallChainStep{step}, chain...)
}

func dedupeNavigationTraces(traces []navigationTrace) []navigationTrace {
	if len(traces) == 0 {
		return nil
	}

	best := make(map[string]navigationTrace)
	order := make([]string, 0, len(traces))
	for _, trace := range traces {
		key := strings.Join([]string{
			trace.Method,
			trace.TargetPage,
			trace.RawTarget,
			fmt.Sprintf("%t", trace.Dynamic),
			trace.SourceFile,
			fmt.Sprintf("%d", trace.LineNumber),
		}, "|")
		current, ok := best[key]
		if !ok {
			best[key] = trace
			order = append(order, key)
			continue
		}
		if len(trace.CallChain) > len(current.CallChain) {
			best[key] = trace
		}
	}

	results := make([]navigationTrace, 0, len(best))
	for _, key := range order {
		results = append(results, best[key])
	}
	return results
}

func buildSharedRouterHelpers(manifest *RouteManifest) []SharedRouterHelper {
	accumulators := make(map[string]*sharedRouterHelperAccumulator)

	for _, edge := range manifest.NavigationEdges {
		for _, step := range edge.CallChain {
			if step.Kind != "shared_helper" {
				continue
			}
			key := step.FilePath + "|" + step.FunctionName
			acc, ok := accumulators[key]
			if !ok {
				acc = &sharedRouterHelperAccumulator{
					filePath:     step.FilePath,
					functionName: step.FunctionName,
					pages:        make(map[string]bool),
					methods:      make(map[string]bool),
					targets:      make(map[string]bool),
				}
				accumulators[key] = acc
			}
			acc.pages[edge.SourcePage] = true
			acc.methods[edge.Method] = true
			if edge.RawTarget != "" {
				acc.targets[edge.RawTarget] = true
			}
			if edge.Dynamic {
				acc.dynamic = true
			}
		}
	}

	results := make([]SharedRouterHelper, 0, len(accumulators))
	for _, acc := range accumulators {
		results = append(results, SharedRouterHelper{
			FilePath:     acc.filePath,
			FunctionName: acc.functionName,
			UsedByPages:  mapKeysSorted(acc.pages),
			Methods:      mapKeysSorted(acc.methods),
			TargetHints:  mapKeysSorted(acc.targets),
			Dynamic:      acc.dynamic,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].FilePath != results[j].FilePath {
			return results[i].FilePath < results[j].FilePath
		}
		return results[i].FunctionName < results[j].FunctionName
	})
	return results
}

func mapKeysSorted(values map[string]bool) []string {
	results := make([]string, 0, len(values))
	for key, ok := range values {
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		results = append(results, key)
	}
	sort.Strings(results)
	if len(results) == 0 {
		return nil
	}
	return results
}

func extractCallChainNavigationEdges(ctx *routeAnalyzerContext, route, jsPath string, actions []wxmlAction) []NavigationEdge {
	module := ctx.loadModule(jsPath)
	if module == nil || len(actions) == 0 {
		return nil
	}

	results := make([]NavigationEdge, 0)
	for _, action := range actions {
		if action.HandlerName == "" {
			continue
		}

		hints := map[string]routeValueHint{}
		if action.RawTarget != "" {
			hints[hintSeedKey] = routeValueHint{
				Raw:     action.RawTarget,
				Dynamic: strings.Contains(action.RawTarget, "{{"),
			}
		}

		traces := ctx.traceFunction(route, module, action.HandlerName, hints, 0, map[string]bool{})
		for _, trace := range traces {
			edge := NavigationEdge{
				SourcePage:   route,
				TargetPage:   trace.TargetPage,
				RawTarget:    trace.RawTarget,
				Method:       trace.Method,
				SourceType:   callChainSourceType(trace.CallChain),
				SourceFile:   action.SourceFile,
				LineNumber:   action.LineNumber,
				HandlerName:  action.HandlerName,
				TriggerEvent: action.TriggerEvent,
				TriggerText:  action.TriggerText,
				Dynamic:      trace.Dynamic,
				CallChain:    trace.CallChain,
			}

			if action.RawTarget != "" && (edge.RawTarget == "" || strings.Contains(edge.RawTarget, "dataset.")) {
				edge.RawTarget = action.RawTarget
				if target, ok := normalizeRouteReference(action.RawTarget, route); ok {
					edge.TargetPage = target
				}
				edge.Dynamic = edge.Dynamic || strings.Contains(action.RawTarget, "{{")
			}
			if edge.TargetPage == "" && edge.RawTarget == "" {
				continue
			}
			results = append(results, edge)
		}
	}

	return dedupeEdges(results)
}

func extractLifecycleNavigationEdges(ctx *routeAnalyzerContext, route, jsPath string) []NavigationEdge {
	module := ctx.loadModule(jsPath)
	if module == nil {
		return nil
	}

	lifecycleHandlers := []string{
		"onLoad",
		"onShow",
		"onReady",
		"onLaunch",
		"created",
		"attached",
	}

	results := make([]NavigationEdge, 0)
	for _, handlerName := range lifecycleHandlers {
		if resolveModuleFunction(module, handlerName) == nil {
			continue
		}

		for _, trace := range ctx.traceFunction(route, module, handlerName, nil, 0, map[string]bool{}) {
			if trace.TargetPage == "" && trace.RawTarget == "" {
				continue
			}
			results = append(results, NavigationEdge{
				SourcePage:  route,
				TargetPage:  trace.TargetPage,
				RawTarget:   trace.RawTarget,
				Method:      trace.Method,
				SourceType:  callChainSourceType(trace.CallChain),
				SourceFile:  jsPath,
				LineNumber:  trace.LineNumber,
				HandlerName: handlerName,
				Dynamic:     trace.Dynamic,
				CallChain:   trace.CallChain,
			})
		}
	}

	return dedupeEdges(results)
}

func callChainSourceType(chain []CallChainStep) string {
	for _, step := range chain {
		if step.Kind == "shared_helper" {
			return "shared-router"
		}
	}
	if len(chain) > 1 {
		return "call-chain"
	}
	return "js"
}

func splitTopLevel(text string, separator rune) []string {
	results := make([]string, 0)
	start := 0
	var quote rune
	escaped := false
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0

	for index, ch := range text {
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}

		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		default:
			if ch == separator && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				results = append(results, strings.TrimSpace(text[start:index]))
				start = index + 1
			}
		}
	}

	results = append(results, strings.TrimSpace(text[start:]))
	return results
}

func topLevelColonIndex(text string) int {
	var quote rune
	escaped := false
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0

	for index, ch := range text {
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}

		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ':':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return index
			}
		}
	}

	return -1
}

func normalizeJSIdentifier(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "...")
	value = strings.Trim(value, "{}[]()")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.IndexAny(value, " ="); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, "."); idx >= 0 {
		return strings.TrimSpace(value)
	}
	return strings.Trim(value, "\"'`")
}

func normalizeJSPropertyName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "["); idx >= 0 {
		value = value[:idx]
	}
	return strings.Trim(normalizeJSIdentifier(value), "\"'`")
}

func trimWrappingParens(value string) string {
	for {
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
			return value
		}
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
}

func nextNonWhitespaceIndex(text string, start int) int {
	for i := start; i < len(text); i++ {
		if !isWhitespace(text[i]) {
			return i
		}
	}
	return -1
}

func prevNonWhitespaceIndex(text string, start int) int {
	for i := start; i >= 0; i-- {
		if !isWhitespace(text[i]) {
			return i
		}
	}
	return -1
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
