package formatter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

func TestAnalyzeJavaScriptRecoversPanic(t *testing.T) {
	originalCore := analyzeJavaScriptCore
	t.Cleanup(func() {
		analyzeJavaScriptCore = originalCore
	})

	analyzeJavaScriptCore = func(input []byte, filePath string) (*DeobfuscationResult, error) {
		panic("模拟 AST 分析崩溃")
	}

	input := []byte("var answer = 42;")
	result, err := AnalyzeJavaScript(input, "pages/index.js")
	if err != nil {
		t.Fatalf("AnalyzeJavaScript 返回错误: %v", err)
	}
	if result == nil {
		t.Fatal("AnalyzeJavaScript 返回 nil 结果")
	}
	if !bytes.Equal(result.Content, input) {
		t.Fatalf("panic 后应保留原始内容，got %q", result.Content)
	}
	if result.Status != "skipped" {
		t.Fatalf("panic 后状态应为 skipped，got %q", result.Status)
	}
}

func TestAnalyzeJavaScriptKeepsDecodedStringEscapesValid(t *testing.T) {
	input := []byte(`var css = "format(\x22truetype\x22);content:\u0022\\e600\u0022";`)
	result, err := AnalyzeJavaScript(input, "app-wxss.js")
	if err != nil {
		t.Fatalf("AnalyzeJavaScript 返回错误: %v", err)
	}
	if _, err := parser.ParseFile(nil, "", string(result.Content), 0); err != nil {
		t.Fatalf("解码后的 JavaScript 不应破坏语法: %v\n%s", err, result.Content)
	}
	output := string(result.Content)
	if !strings.Contains(output, `format(\"truetype\")`) {
		t.Fatalf("字符串内部引号应保持转义，got %q", output)
	}
	if !strings.Contains(output, `content:\"\\e600\"`) {
		t.Fatalf("字符串内部反斜杠与引号应保持转义，got %q", output)
	}
}

func TestASTHelpersSkipIncompleteNodes(t *testing.T) {
	analysis := &bootstrapAnalysis{
		arrays:     make(map[string]struct{}),
		decoders:   make(map[string]struct{}),
		techniques: make(map[string]struct{}),
	}

	statement := &ast.VariableStatement{
		List: []*ast.Binding{
			nil,
			{},
			{Target: &ast.Identifier{}},
		},
	}

	if markStringArrayStatement(statement, analysis) {
		t.Fatal("不完整变量声明不应被识别为字符串数组")
	}
	if markDecoderVarStatement(statement, analysis) {
		t.Fatal("不完整变量声明不应被识别为解码器")
	}
	if got := dedupeStatements([]ast.Statement{nil, statement, statement}); len(got) != 1 {
		t.Fatalf("dedupeStatements 应跳过 nil 并去重，got %d", len(got))
	}
}

func TestWalkNodeSkipsTypedNilNode(t *testing.T) {
	var identifier *ast.Identifier
	called := false

	walkNode(identifier, func(node ast.Node) {
		called = true
	})

	if called {
		t.Fatal("walkNode 不应访问 typed nil AST 节点")
	}
}

func TestHTMLFormatterFallsBackWhenScriptAnalysisPanics(t *testing.T) {
	originalCore := analyzeJavaScriptCore
	t.Cleanup(func() {
		analyzeJavaScriptCore = originalCore
	})

	analyzeJavaScriptCore = func(input []byte, filePath string) (*DeobfuscationResult, error) {
		panic("模拟内嵌脚本分析崩溃")
	}

	input := []byte("<html><body><script>var answer=42;</script></body></html>")
	output, err := NewHTMLFormatter().Format(input)
	if err != nil {
		t.Fatalf("HTMLFormatter 返回错误: %v", err)
	}
	if !bytes.Contains(output, []byte("var answer = 42;")) {
		t.Fatalf("HTMLFormatter 应保留原始脚本内容，got %q", output)
	}
}
