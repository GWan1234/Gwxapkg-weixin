package formatter

import (
	"bytes"

	. "github.com/25smoking/Gwxapkg/internal/config"
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
)

// JSFormatter 结构体，用于格式化 JavaScript 代码
type JSFormatter struct{}

// NewJSFormatter 创建一个新的 JSFormatter 实例
func NewJSFormatter() *JSFormatter {
	return &JSFormatter{}
}

// Format 方法用于格式化 JavaScript 代码
// input: 原始的 JavaScript 代码字节切片
// 返回值: 格式化后的 JavaScript 代码字节切片和错误信息（如果有）
func (f *JSFormatter) Format(input []byte) ([]byte, error) {
	formatted, _, err := f.FormatFile(input, "")
	return formatted, err
}

// FormatFile 按文件路径格式化并返回反混淆元数据
func (f *JSFormatter) FormatFile(input []byte, filePath string) ([]byte, *DeobfuscationResult, error) {
	configManager := NewSharedConfigManager()
	if value, ok := configManager.Get("fast"); ok {
		if fast, ok := value.(bool); ok && fast {
			// 快速模式用于与纯解包工具对标：跳过 AST 反混淆，也跳过
			// 对几十 MB 运行时脚本代价很高的美化。工程还原仍会照常执行。
			return bytes.TrimSpace(input), nil, nil
		}
	}

	result, err := AnalyzeJavaScript(input, filePath)
	if err != nil {
		return input, result, err
	}

	output := bytes.TrimSpace(result.Content)
	output = formatJavaScriptOutput(output, result, configManager)
	return output, result, nil
}

func formatJavaScriptOutput(output []byte, result *DeobfuscationResult, configManager *SharedConfigManager) []byte {
	pretty := true
	if value, ok := configManager.Get("pretty"); ok {
		if enabled, ok := value.(bool); ok {
			pretty = enabled
		}
	}

	if pretty {
		code := string(output)
		beautifiedCode, beautifyErr := jsbeautifier.Beautify(&code, jsbeautifier.DefaultOptions())
		if beautifyErr == nil {
			output = []byte(beautifiedCode)
		}
	}

	if result != nil && result.IsObfuscated {
		output = prependObfuscatedHeader(output, result)
	}
	return output
}

func init() {
	RegisterFormatter(".js", NewJSFormatter())
}
