package configfile

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 用户/项目级默认配置。
type Config struct {
	RuleTier    string `yaml:"rule_tier"`
	ASTRename   string `yaml:"ast_rename"`
	ASTMaxSize  string `yaml:"ast_max_size"`
	BaseURL     string `yaml:"base_url"`
	Postman     *bool  `yaml:"postman"`
	Sensitive   *bool  `yaml:"sensitive"`
	SkipVendor  *bool  `yaml:"skip_vendor"`
	OutputRoot  string `yaml:"output_root"`
	ExportSARIF *bool  `yaml:"export_sarif"`
	ExportOpenAPI *bool `yaml:"export_openapi"`
}

// Load 依次尝试 ./.gwxapkg.yaml 与 ~/.gwxapkg.yaml。
func Load() (*Config, string, error) {
	candidates := []string{
		".gwxapkg.yaml",
		".gwxapkg.yml",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".gwxapkg.yaml"),
			filepath.Join(home, ".gwxapkg.yml"),
		)
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, path, err
		}
		return &cfg, path, nil
	}
	return &Config{}, "", nil
}

// Bool 读取可选布尔，缺省返回 fallback。
func Bool(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}
