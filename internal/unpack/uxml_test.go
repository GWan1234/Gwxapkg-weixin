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
