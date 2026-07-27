package scanner

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

const maxRequestASTFileBytes = 400 * 1024

// ExtractAPIEndpointsAST 使用 AST 提取 request/fetch 调用，作为正则提取的补充。
// 失败时返回 nil（调用方应回退正则结果）。
func ExtractAPIEndpointsAST(filePath, text string) (endpoints []APIEndpoint) {
	defer func() {
		if recover() != nil {
			endpoints = nil
		}
	}()

	if len(text) == 0 || len(text) > maxRequestASTFileBytes {
		return nil
	}
	if !looksLikeAPIContent(text) {
		return nil
	}

	program, err := parser.ParseFile(nil, filePath, text, parser.IgnoreRegExpErrors, parser.WithDisableSourceMaps)
	if err != nil || program == nil {
		return nil
	}

	// 同文件内简单常量：const/var/let name = "literal"
	constants := map[string]string{}
	collectStringConstants(program, constants)

	seen := make(map[string]struct{})
	var walk func(node interface{})
	walk = func(node interface{}) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *ast.Program:
			for _, stmt := range n.Body {
				walk(stmt)
			}
		case *ast.ExpressionStatement:
			walk(n.Expression)
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				walk(stmt)
			}
		case *ast.CallExpression:
			if ep, ok := endpointFromCall(filePath, text, n, constants); ok {
				key := ep.Method + ":" + ep.RawURL
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					endpoints = append(endpoints, ep)
				}
			}
			walk(n.Callee)
			for _, arg := range n.ArgumentList {
				walk(arg)
			}
		case *ast.AssignExpression:
			walk(n.Left)
			walk(n.Right)
		case *ast.BinaryExpression:
			walk(n.Left)
			walk(n.Right)
		case *ast.VariableStatement:
			collectBindings(n.List, constants)
			for _, d := range n.List {
				walk(d)
			}
		case *ast.LexicalDeclaration:
			collectBindings(n.List, constants)
			for _, d := range n.List {
				walk(d)
			}
		case *ast.FunctionDeclaration:
			if n.Function != nil {
				walk(n.Function)
			}
		case *ast.Binding:
			if n.Initializer != nil {
				walk(n.Initializer)
			}
		case *ast.FunctionLiteral:
			if n.Body != nil {
				walk(n.Body)
			}
		case *ast.ObjectLiteral:
			for _, prop := range n.Value {
				walk(prop)
			}
		case *ast.PropertyKeyed:
			walk(n.Value)
		case *ast.ReturnStatement:
			walk(n.Argument)
		case *ast.IfStatement:
			walk(n.Test)
			walk(n.Consequent)
			walk(n.Alternate)
		}
	}
	walk(program)
	return endpoints
}

func collectStringConstants(program *ast.Program, out map[string]string) {
	if program == nil {
		return
	}
	for _, stmt := range program.Body {
		switch n := stmt.(type) {
		case *ast.VariableStatement:
			collectBindings(n.List, out)
		case *ast.LexicalDeclaration:
			collectBindings(n.List, out)
		}
	}
}

func collectBindings(list []*ast.Binding, out map[string]string) {
	for _, b := range list {
		if b == nil || b.Target == nil || b.Initializer == nil {
			continue
		}
		id, ok := b.Target.(*ast.Identifier)
		if !ok || id == nil {
			continue
		}
		if lit, ok := b.Initializer.(*ast.StringLiteral); ok && lit != nil {
			out[id.Name.String()] = lit.Value.String()
		}
	}
}

func endpointFromCall(filePath, text string, call *ast.CallExpression, constants map[string]string) (APIEndpoint, bool) {
	if call == nil || len(call.ArgumentList) == 0 {
		return APIEndpoint{}, false
	}

	callee := calleeName(call.Callee)
	method := "UNKNOWN"
	switch {
	case strings.HasSuffix(callee, ".request") || callee == "request" || callee == "fetch":
		// ok
	case strings.Contains(callee, "axios."):
		parts := strings.Split(callee, ".")
		method = strings.ToUpper(parts[len(parts)-1])
	default:
		// axios.get style already handled; generic *.get/post
		if parts := strings.Split(callee, "."); len(parts) > 1 {
			last := strings.ToLower(parts[len(parts)-1])
			switch last {
			case "get", "post", "put", "delete", "patch", "head", "options":
				method = strings.ToUpper(last)
			default:
				return APIEndpoint{}, false
			}
		} else {
			return APIEndpoint{}, false
		}
	}

	rawURL := ""
	// 第一个参数是字符串 / 标识符 / 模板
	rawURL = resolveStringExpr(call.ArgumentList[0], constants)
	// 或对象参数 { url, method }
	if rawURL == "" {
		if obj, ok := call.ArgumentList[0].(*ast.ObjectLiteral); ok && obj != nil {
			rawURL, method = urlAndMethodFromObject(obj, constants, method)
		}
	}
	// axios.get(url) 第二个参数不重要
	if rawURL == "" && len(call.ArgumentList) > 0 {
		rawURL = resolveStringExpr(call.ArgumentList[0], constants)
	}
	if !isLikelyAPIURL(rawURL) {
		return APIEndpoint{}, false
	}

	start := 0
	if idx := call.Idx0(); idx > 0 {
		start = int(idx) - 1
		if start < 0 {
			start = 0
		}
	}
	return buildEndpoint(filePath, text, start, start+1, method, rawURL, "ast-request"), true
}

func calleeName(expr ast.Expression) string {
	switch n := expr.(type) {
	case *ast.Identifier:
		if n == nil {
			return ""
		}
		return n.Name.String()
	case *ast.DotExpression:
		if n == nil {
			return ""
		}
		left := calleeName(n.Left)
		if left == "" {
			return n.Identifier.Name.String()
		}
		return left + "." + n.Identifier.Name.String()
	default:
		return ""
	}
}

func resolveStringExpr(expr ast.Expression, constants map[string]string) string {
	switch n := expr.(type) {
	case *ast.StringLiteral:
		if n == nil {
			return ""
		}
		return n.Value.String()
	case *ast.Identifier:
		if n == nil {
			return ""
		}
		if v, ok := constants[n.Name.String()]; ok {
			return v
		}
	case *ast.BinaryExpression:
		// base + "/path"
		if n != nil && n.Operator.String() == "+" {
			left := resolveStringExpr(n.Left, constants)
			right := resolveStringExpr(n.Right, constants)
			if left != "" || right != "" {
				return left + right
			}
		}
	case *ast.TemplateLiteral:
		if n == nil {
			return ""
		}
		// 仅拼接静态片段；有表达式时保留前缀
		var b strings.Builder
		for i, part := range n.Elements {
			if part == nil {
				continue
			}
			b.WriteString(part.Literal)
			// Elements 通常交错：static, (expr), static...
			if i < len(n.Expressions) {
				b.WriteString("${...}")
			}
		}
		s := b.String()
		// 去掉模板引号风格的噪声
		s = strings.Trim(s, "`")
		if strings.Contains(s, "${...}") {
			if idx := strings.Index(s, "${...}"); idx > 0 {
				return s[:idx]
			}
			return ""
		}
		return s
	}
	return ""
}

func urlAndMethodFromObject(obj *ast.ObjectLiteral, constants map[string]string, method string) (string, string) {
	urlValue := ""
	for _, prop := range obj.Value {
		keyed, ok := prop.(*ast.PropertyKeyed)
		if !ok || keyed == nil {
			continue
		}
		key := propertyKeyName(keyed.Key)
		switch strings.ToLower(key) {
		case "url":
			urlValue = resolveStringExpr(keyed.Value, constants)
		case "method", "type":
			if m := resolveStringExpr(keyed.Value, constants); m != "" {
				method = strings.ToUpper(m)
			}
		}
	}
	return urlValue, method
}

func propertyKeyName(expr ast.Expression) string {
	switch n := expr.(type) {
	case *ast.StringLiteral:
		return n.Value.String()
	case *ast.Identifier:
		return n.Name.String()
	default:
		return ""
	}
}
