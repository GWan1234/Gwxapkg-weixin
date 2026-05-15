package unpack

import (
	"strings"
	"testing"
)

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
