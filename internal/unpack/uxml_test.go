package unpack

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func TestGetFinalResultInterruptsStuckWXMLGenerator(t *testing.T) {
	vm := goja.New()
	value, err := vm.RunString(`(function(){ for (;;) {} })`)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = getFinalResult(vm, value)
	if !isWXMLRenderTimeout(err) {
		t.Fatalf("应返回 WXML 执行超时，实际: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("超时中断过慢: %s", elapsed)
	}
}

func TestGetDomTreeUnwrapsVirtualNodes(t *testing.T) {
	node := map[string]interface{}{
		"tag": "wx-page",
		"children": []interface{}{
			map[string]interface{}{
				"tag": "virtual",
				"children": []interface{}{
					map[string]interface{}{
						"tag":      "wx-view",
						"attr":     map[string]interface{}{"class": "content"},
						"children": []interface{}{"hello\n"},
					},
				},
			},
		},
	}

	content := getDomTree(node)
	if strings.Contains(content, "<virtual") {
		t.Fatalf("虚拟节点不应作为真实 WXML 标签输出: %s", content)
	}
	if !strings.Contains(content, `<view class="content">`) {
		t.Fatalf("应保留虚拟节点下的真实子节点: %s", content)
	}
}

func TestGetFucMatchesRootWXMLWithoutElseAndDoubleQuotes(t *testing.T) {
	code := `
	__wxAppCode__["./base.wxml"] = $gwx("./base.wxml");
	else __wxAppCode__['./pages/home/index.wxml'] = $gwx('./pages/home/index.wxml');
	`

	gwx := map[string]interface{}{}
	getFuc(code, gwx)

	if gwx["./base.wxml"] != `$gwx("./base.wxml");` {
		t.Fatalf("应提取无 else 且双引号的 base.wxml，实际: %#v", gwx)
	}
	if gwx["./pages/home/index.wxml"] != `$gwx('./pages/home/index.wxml');` {
		t.Fatalf("应保留原有 else 注册形式，实际: %#v", gwx)
	}
}

func TestExtractFuncNameAndArgsSupportsDoubleQuotes(t *testing.T) {
	funcName, args := extractFuncNameAndArgs(`$gwx0("./sub-pages/demo/index.wxml");`)

	if funcName != "$gwx0" {
		t.Fatalf("函数名提取错误: %s", funcName)
	}
	if len(args) != 1 || args[0] != "./sub-pages/demo/index.wxml" {
		t.Fatalf("参数提取错误: %#v", args)
	}
}

func TestWXMLModuleAliasesIncludeRootAndRelativeForms(t *testing.T) {
	aliases := wxmlModuleAliases("./base.wxml")
	want := []string{"./base.wxml", "base.wxml"}
	if strings.Join(aliases, ",") != strings.Join(want, ",") {
		t.Fatalf("base.wxml 别名错误: %#v", aliases)
	}

	aliases = wxmlModuleAliases("./sub-pages/demo/index.wxml")
	want = []string{"./sub-pages/demo/index.wxml", "sub-pages/demo/index.wxml"}
	if strings.Join(aliases, ",") != strings.Join(want, ",") {
		t.Fatalf("子包 wxml 别名错误: %#v", aliases)
	}
}

func TestBuildWXMLModuleRegistrationScriptRegistersAliases(t *testing.T) {
	script := buildWXMLModuleRegistrationScript(map[string]interface{}{
		"./base.wxml": `$gwx("./base.wxml");`,
	})

	for _, want := range []string{
		`__wxAppCode__["./base.wxml"]=$gwx("./base.wxml");`,
		`__wxAppCode__["base.wxml"]=$gwx("./base.wxml");`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("注册脚本缺少 %s，实际:\n%s", want, script)
		}
	}
}

func TestCollectDirectWXMLGenerateCallsFromHTMLWrapper(t *testing.T) {
	code := `var gf = $gwx('./base.wxml');`
	gwx := map[string]interface{}{}

	collectDirectWXMLGenerateCalls(code, gwx)

	if gwx["./base.wxml"] != `$gwx('./base.wxml');` {
		t.Fatalf("应从 HTML wrapper 提取 base.wxml 生成函数，实际: %#v", gwx)
	}
}

func TestHasWXMLFunctionDefinitionSkipsSideEffectOnlyWrapper(t *testing.T) {
	if hasWXMLFunctionDefinition(`__wxAppCode__['pages/demo/index.wxss'](); var gf=$gwx7_XC_1('./pages/demo/index.wxml');`) {
		t.Fatal("仅调用生成函数的 HTML wrapper 不应作为 VM 脚本执行")
	}
	if !hasWXMLFunctionDefinition(`var $gwx7_XC_1 = function(path) { return function() {}; };`) {
		t.Fatal("包含 $gwx 定义的 HTML wrapper 应保留执行")
	}
}

func TestExtractWXMLFunctionDefinitionsRemovesWrapperSideEffects(t *testing.T) {
	source := `getApp().globalData.appId;
var $gwx7_XC_1 = function(path) { return function() { return path; }; };
__wxAppCode__["pages/demo/index.wxss"]();`

	definitions := extractWXMLFunctionDefinitions(source)
	if !strings.Contains(definitions, `$gwx7_XC_1 = function`) {
		t.Fatalf("应保留 $gwx 定义，实际: %s", definitions)
	}
	if strings.Contains(definitions, "getApp") || strings.Contains(definitions, ".wxss") {
		t.Fatalf("不应执行 wrapper 运行时副作用，实际: %s", definitions)
	}
}

func TestBuildTaroStaticWXMLUsesRelativeBaseImport(t *testing.T) {
	content := buildTaroStaticWXML("./sub-pages/hospital-info/department-list/index.wxml", "taro_tmpl")

	if !strings.Contains(content, `<import src="../../../base.wxml" />`) {
		t.Fatalf("子包页面应生成指向根 base.wxml 的相对 import，实际:\n%s", content)
	}
	if !strings.Contains(content, `<template is="taro_tmpl" data="{{root:root}}" />`) {
		t.Fatalf("应生成 Taro 模板调用，实际:\n%s", content)
	}
}

func TestBuildTaroBaseWXMLIncludesTemplateStubs(t *testing.T) {
	script := `d_[x[0]]["taro_tmpl"] = function(){}
d_[x[0]]["tmpl_0_view"] = function(){}`

	content := buildTaroBaseWXML(script)

	for _, want := range []string{
		`<template name="taro_tmpl">`,
		`<template name="tmpl_0_undefined">`,
		`<template name="tmpl_0_view">`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("base.wxml fallback 缺少 %s，实际:\n%s", want, content)
		}
	}
}

func TestLoadWXMLRuntimeLoadsSourcesOnceAndSharesDefinitions(t *testing.T) {
	sources := []string{
		`var __fixtureLoads = 1;
function buildFixtureNode(text) {
  return {tag: "wx-page", children: [{tag: "wx-view", attr: {}, children: [text]}]};
}`,
		`__fixtureLoads += 1;
var $gwx7_XC_22 = function(path) {
  return function() { return buildFixtureNode(path); };
};`,
	}
	gwx := map[string]interface{}{
		"pages/demo/index.wxml": `$gwx7_XC_22('pages/demo/index.wxml');`,
	}

	vm, scriptErrors, err := loadWXMLRuntime(sources, gwx, false)
	if err != nil {
		t.Fatalf("初始化 WXML 运行时失败: %v", err)
	}
	if len(scriptErrors) != 0 {
		t.Fatalf("脚本不应加载失败: %#v", scriptErrors)
	}
	if loads := vm.Get("__fixtureLoads").ToInteger(); loads != 2 {
		t.Fatalf("每段脚本应只执行一次，实际计数: %d", loads)
	}
	content, err := renderWXMLModule(vm, "pages/demo/index.wxml", gwx["pages/demo/index.wxml"].(string), "")
	if err != nil {
		t.Fatalf("分包函数应在共享运行时中可用: %v", err)
	}
	if !strings.Contains(content, "pages/demo/index.wxml") {
		t.Fatalf("还原的 WXML 内容错误: %s", content)
	}
}

func TestRenderWXMLBatchUsesFunctionFromAdditionalHTMLScript(t *testing.T) {
	sources := []string{
		`var mainFrameLoaded = true;`,
		`var $gwx9_XC_3 = function(path) {
  return function() {
    return {tag: "wx-page", children: [{tag: "wx-text", attr: {}, children: ["subpackage"]}]};
  };
};`,
	}
	gwx := map[string]interface{}{
		"subpackage/page.wxml": `$gwx9_XC_3('subpackage/page.wxml');`,
	}

	results, report, err := renderWXMLBatch(sources, gwx, false)
	if err != nil {
		t.Fatalf("批量还原失败: %v", err)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("不应再出现 $gwx*_XC_* 函数断言失败: %#v", report.Failures)
	}
	if !strings.Contains(results["subpackage/page.wxml"], "<text>") {
		t.Fatalf("应使用附加 HTML 脚本还原 WXML: %#v", results)
	}
}

func TestRenderWXMLBatchRecoversFunctionDeclaredAfterRuntimeError(t *testing.T) {
	sources := []string{`throw new Error("fixture init failed");
var $gwx7_XC_21 = function(path) {
  return function() {
    return {tag: "wx-page", children: [{tag: "wx-view", attr: {}, children: ["recovered"]}]};
  };
};`}
	gwx := map[string]interface{}{
		"subpackage/recovered.wxml": `$gwx7_XC_21('subpackage/recovered.wxml');`,
	}

	results, report, err := renderWXMLBatch(sources, gwx, false)
	if err != nil {
		t.Fatalf("批量还原失败: %v", err)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("初始化异常后的 $gwx 函数应可由 AST 恢复: %#v", report.Failures)
	}
	if !strings.Contains(results["subpackage/recovered.wxml"], "recovered") {
		t.Fatalf("恢复结果错误: %#v", results)
	}
}

func TestRenderWXMLBatchReadsCodeSpaceRegisteredTemplate(t *testing.T) {
	sources := []string{`
var __wxCodeSpace__ = {
  batchAddCompiledTemplate: function(factory) {
    var templates = factory({}, {}, {}, {}, function(value) { return value; }, {}, {}, {}, {});
    for (var path in templates) {
      __wxAppCode__[path + ".wxml"] = templates[path];
    }
  }
};`, `
__wxCodeSpace__.batchAddCompiledTemplate(function() {
  return {
    "subpackage/runtime/index": function() {
      return {tag: "wx-page", children: [{tag: "wx-view", attr: {}, children: ["codespace"]}]};
    }
  };
});`}

	results, report, err := renderWXMLBatch(sources, map[string]interface{}{}, true)
	if err != nil {
		t.Fatalf("批量还原失败: %v", err)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("CodeSpace 模板不应被跳过: %#v", report.Failures)
	}
	if !strings.Contains(results["subpackage/runtime/index.wxml"], "codespace") {
		t.Fatalf("应从 __wxAppCode__ 读取 CodeSpace 模板: %#v", results)
	}
}

func syntheticWXMLBenchmarkFixture(pageCount int) (string, map[string]interface{}) {
	source := strings.Repeat("/* compiled view runtime padding */", 1600) + `
var $gwxSynthetic = function(path) {
  return function() {
    return {tag: "wx-page", children: [{tag: "wx-view", attr: {}, children: [path]}]};
  };
};`
	gwx := make(map[string]interface{}, pageCount)
	for i := 0; i < pageCount; i++ {
		path := fmt.Sprintf("subpackage/page-%03d.wxml", i)
		gwx[path] = fmt.Sprintf("$gwxSynthetic(%q);", path)
	}
	return source, gwx
}

func BenchmarkRenderWXMLBatch91Pages(b *testing.B) {
	source, gwx := syntheticWXMLBenchmarkFixture(91)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, report, err := renderWXMLBatch([]string{source}, gwx, false)
		if err != nil || len(report.Failures) != 0 || len(results) != len(gwx) {
			b.Fatalf("批量还原异常: results=%d failures=%d err=%v", len(results), len(report.Failures), err)
		}
	}
}

// 保留旧执行形态的对照基准：每个页面重新初始化一次整份视图运行时。
func BenchmarkRenderWXMLPerPageLegacyShape91Pages(b *testing.B) {
	source, gwx := syntheticWXMLBenchmarkFixture(91)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for path, gencode := range gwx {
			one := map[string]interface{}{path: gencode}
			results, report, err := renderWXMLBatch([]string{source}, one, false)
			if err != nil || len(report.Failures) != 0 || len(results) != 1 {
				b.Fatalf("逐页还原异常: results=%d failures=%d err=%v", len(results), len(report.Failures), err)
			}
		}
	}
}
