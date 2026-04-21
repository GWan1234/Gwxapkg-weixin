package scanner

import (
	"regexp"
	"strings"
)

var nonAlnumPattern = regexp.MustCompile(`[^a-z0-9]+`)

var exactCategoryMap = map[string]string{
	"path":         "path",
	"url":          "url",
	"api_endpoint": "url",
	"domain":       "domain",

	"email":      "contact",
	"phone_cn":   "contact",
	"id_card_cn": "contact",

	"ipv4":        "network",
	"internal_ip": "network",
	"mac_address": "network",

	"credit_card":        "payment",
	"uuid":               "artifact",
	"base64_long":        "artifact",
	"hex_key":            "artifact",
	"ssh_rsa_public":     "artifact",
	"ssh_ed25519_public": "artifact",
	"md5_hash":           "artifact",
	"sha1_hash":          "artifact",
	"sha256_hash":        "artifact",

	"jdbc_mysql":            "database",
	"jdbc_postgresql":       "database",
	"jdbc_oracle":           "database",
	"jdbc_sqlserver":        "database",
	"jdbc_db2":              "database",
	"mongodb_connection":    "database",
	"redis_connection":      "database",
	"postgres_connection":   "database",
	"mysql_connection":      "database",
	"db_username":           "database",
	"db_password":           "database",
	"db_host":               "database",
	"elasticsearch_url":     "database",
	"cassandra_connection":  "database",
	"influxdb_connection":   "database",
	"basic_auth":            "token",
	"json_web_token":        "token",
	"jwt_token_full":        "token",
	"oauth_access_token":    "token",
	"oauth_refresh_token":   "token",
	"bearer_token":          "token",
	"authorization_token":   "token",
	"api_token":             "token",
	"auth_token":            "token",
	"session_token":         "token",
	"csrf_token":            "token",
	"xsrf_token":            "token",
	"service_account_token": "token",
	"machine_token":         "token",
	"encryption_token":      "token",
	"verification_token":    "token",

	"deploy_token":          "devops",
	"build_token":           "devops",
	"ci_token":              "devops",
	"runner_token":          "devops",
	"pipeline_token":        "devops",
	"registry_token":        "devops",
	"personal_access_token": "devops",

	"password_generic":    "password",
	"username_password":   "password",
	"admin_password":      "password",
	"root_password":       "password",
	"default_password":    "password",
	"test_password":       "password",
	"ftp_password":        "password",
	"smtp_password":       "password",
	"ldap_password":       "password",
	"vpn_password":        "password",
	"wifi_password":       "password",
	"encryption_password": "password",
	"maven_password":      "password",

	"api_key_generic":    "api_key",
	"access_key_generic": "api_key",
	"nuget_api_key":      "api_key",

	"secret_key_generic":  "secret",
	"encryption_key":      "secret",
	"master_key":          "secret",
	"signing_key":         "secret",
	"session_secret":      "secret",
	"client_secret":       "secret",
	"app_secret":          "secret",
	"token_secret":        "secret",
	"webhook_secret":      "secret",
	"oauth_client_secret": "secret",
	"paypal_secret":       "payment",

	"private_key_rsa":     "private_key",
	"private_key_dsa":     "private_key",
	"private_key_ec":      "private_key",
	"private_key_openssh": "private_key",
	"private_key_pkcs8":   "private_key",
	"pgp_private_key":     "private_key",
	"certificate":         "private_key",

	"aws_access_key_id":     "cloud",
	"aws_secret_access_key": "cloud",
	"aws_session_token":     "cloud",
	"aws_account_id":        "cloud",
	"aws_arn":               "cloud",
	"aws_s3_bucket":         "cloud",
	"aliyun_access_key":     "cloud",
	"tencent_secret_id":     "cloud",
	"tencent_secret_key":    "cloud",
	"tencent_api_gateway":   "cloud",
	"huawei_ak":             "cloud",
	"google_api_key":        "cloud",
	"google_oauth":          "cloud",
	"google_cloud_key":      "cloud",
	"azure_client_secret":   "cloud",
	"azure_tenant_id":       "cloud",
	"volcengine_ak":         "cloud",
	"kingsoft_ak":           "cloud",
	"jdcloud_ak":            "cloud",
	"baidu_ak":              "cloud",
	"cloudflare_api_token":  "cloud",
	"digitalocean_token":    "cloud",
	"heroku_api_key":        "cloud",
	"ibm_cloud_api_key":     "cloud",
	"databricks_token":      "cloud",

	"stripe_live_key":   "payment",
	"stripe_test_key":   "payment",
	"stripe_public_key": "payment",
	"paypal_client_id":  "payment",
	"square_token":      "payment",
	"square_secret":     "payment",
	"braintree_token":   "payment",
	"razorpay_key":      "payment",
	"alipay_key":        "payment",
	"wechatpay_key":     "payment",
	"shopify_token":     "payment",

	"slack_token":             "messaging",
	"slack_webhook":           "messaging",
	"discord_token":           "messaging",
	"discord_webhook":         "messaging",
	"telegram_bot_token":      "messaging",
	"wechat_webhook":          "messaging",
	"dingtalk_webhook":        "messaging",
	"dingtalk_appkey":         "messaging",
	"feishu_webhook":          "messaging",
	"feishu_app_secret":       "messaging",
	"twilio_account_sid":      "messaging",
	"twilio_auth_token":       "messaging",
	"sendgrid_api_key":        "messaging",
	"mailgun_api_key":         "messaging",
	"microsoft_teams_webhook": "messaging",

	"github_pat":          "devops",
	"github_oauth":        "devops",
	"github_app_token":    "devops",
	"gitlab_pat":          "devops",
	"gitlab_runner_token": "devops",
	"bitbucket_token":     "devops",
	"npm_token":           "devops",
	"pypi_token":          "devops",
	"docker_hub_token":    "devops",
	"circleci_token":      "devops",
	"travis_token":        "devops",
	"jenkins_token":       "devops",
	"codecov_token":       "devops",
	"sonar_token":         "devops",
	"terraform_token":     "devops",
	"ansible_vault":       "devops",
	"jfrog_token":         "devops",
	"artifactory_token":   "devops",
	"postman_api_key":     "devops",

	"datadog_api_key":       "observability",
	"newrelic_api_key":      "observability",
	"sentry_dsn":            "observability",
	"bugsnag_api_key":       "observability",
	"amplitude_api_key":     "observability",
	"segment_write_key":     "observability",
	"mixpanel_token":        "observability",
	"grafana_api_key":       "observability",
	"grafana_cloud_token":   "observability",
	"grafana_service_token": "observability",
	"pagerduty_api_key":     "observability",
	"opsgenie_api_key":      "observability",

	"shodan_api_key":             "security",
	"censys_api_key":             "security",
	"virustotal_api_key":         "security",
	"abuseipdb_api_key":          "security",
	"auth0_management_api_token": "security",

	"algolia_api_key":        "saas",
	"mapbox_access_token":    "saas",
	"notion_token":           "saas",
	"facebook_access_token":  "saas",
	"facebook_app_secret":    "saas",
	"twitter_api_key":        "saas",
	"twitter_api_secret":     "saas",
	"twitter_bearer_token":   "saas",
	"linkedin_client_secret": "saas",
	"instagram_access_token": "saas",

	"wechat_appid":  "wechat",
	"wechat_corpid": "wechat",
	"wechat_secret": "wechat",
}

var categoryNames = map[string]string{
	"path":          "路径",
	"url":           "URL/API",
	"domain":        "域名",
	"contact":       "联系信息",
	"network":       "网络标识",
	"database":      "数据库与连接",
	"password":      "密码",
	"api_key":       "API 密钥",
	"secret":        "Secret/密钥",
	"token":         "Token/令牌",
	"private_key":   "私钥与证书",
	"artifact":      "编码与指纹",
	"cloud":         "云平台",
	"payment":       "支付与电商",
	"messaging":     "通知与协作",
	"devops":        "开发与交付",
	"observability": "监控与告警",
	"security":      "安全平台",
	"saas":          "第三方 SaaS",
	"wechat":        "微信生态",
	"other":         "其他",
}

var ruleNames = map[string]string{
	"email":                "邮箱",
	"phone_cn":             "手机号",
	"id_card_cn":           "身份证",
	"ipv4":                 "IP 地址",
	"path":                 "路径",
	"url":                  "URL",
	"api_endpoint":         "API 端点",
	"domain":               "域名",
	"password_generic":     "密码",
	"admin_password":       "管理员密码",
	"root_password":        "Root 密码",
	"api_key_generic":      "API 密钥",
	"aws_access_key_id":    "AWS Access Key",
	"aliyun_access_key":    "阿里云 Access Key",
	"tencent_secret_id":    "腾讯云 Secret ID",
	"google_api_key":       "Google API Key",
	"private_key_rsa":      "RSA 私钥",
	"private_key_dsa":      "DSA 私钥",
	"private_key_ec":       "EC 私钥",
	"wechat_appid":         "微信 AppID",
	"wechat_secret":        "微信 Secret",
	"jdbc_mysql":           "MySQL 连接",
	"mongodb_connection":   "MongoDB 连接",
	"redis_connection":     "Redis 连接",
	"cloudflare_api_token": "Cloudflare Token",
	"stripe_live_key":      "Stripe Live Key",
	"slack_webhook":        "Slack Webhook",
	"github_pat":           "GitHub PAT",
	"datadog_api_key":      "Datadog API Key",
}

// GetCategoryKey 根据 rule_id 获取分类 key。
func GetCategoryKey(ruleID string) string {
	normalized := normalizeRuleID(ruleID)
	if normalized == "" {
		return "other"
	}

	if category, ok := exactCategoryMap[normalized]; ok {
		return category
	}

	switch {
	case hasAnyFragment(normalized, "wechatpay", "paypal", "stripe", "square", "braintree", "razorpay", "alipay", "shopify"):
		return "payment"
	case hasAnyFragment(normalized, "aws", "aliyun", "tencent", "qcloud", "azure", "google_cloud", "cloudflare", "digitalocean", "heroku", "ibm_cloud", "volcengine", "kingsoft", "jdcloud", "baidu", "huawei", "databricks", "s3_bucket", "arn"):
		return "cloud"
	case hasAnyFragment(normalized, "slack", "discord", "telegram", "twilio", "sendgrid", "mailgun", "dingtalk", "feishu", "teams_webhook", "webhook"):
		return "messaging"
	case hasAnyFragment(normalized, "github", "gitlab", "bitbucket", "npm", "pypi", "docker", "circleci", "travis", "jenkins", "codecov", "sonar", "terraform", "ansible", "jfrog", "artifactory", "maven", "nuget", "runner", "pipeline", "registry", "deploy", "build", "ci_token", "postman"):
		return "devops"
	case hasAnyFragment(normalized, "datadog", "newrelic", "sentry", "bugsnag", "amplitude", "segment", "mixpanel", "grafana", "pagerduty", "opsgenie"):
		return "observability"
	case hasAnyFragment(normalized, "auth0", "shodan", "censys", "virustotal", "abuseipdb", "alienvault", "oauth"):
		return "security"
	case hasAnyFragment(normalized, "wechat", "weixin"):
		return "wechat"
	case hasAnyFragment(normalized, "private_key", "pgp_private_key", "certificate"):
		return "private_key"
	case looksLikeSaaSCredential(normalized):
		return "saas"
	case hasAnyFragment(normalized, "password", "passwd", "pwd"):
		return "password"
	case hasAnyFragment(normalized, "api_key", "apikey", "access_key"):
		return "api_key"
	case hasAnyFragment(normalized, "token", "bearer", "auth", "jwt"):
		return "token"
	case hasAnyFragment(normalized, "secret", "client_id", "client_secret", "signing_key", "master_key", "encryption_key", "session_secret", "app_secret"):
		return "secret"
	case hasAnyFragment(normalized, "jdbc", "mongodb", "redis", "postgres", "mysql_connection", "db_", "database", "cassandra", "influxdb", "elasticsearch"):
		return "database"
	case hasAnyFragment(normalized, "phone", "email", "id_card"):
		return "contact"
	case hasAnyFragment(normalized, "ipv4", "internal_ip", "mac_address"):
		return "network"
	case hasAnyFragment(normalized, "hash", "base64", "uuid", "public", "hex_key"):
		return "artifact"
	default:
		return "other"
	}
}

// GetCategoryName 获取分类中文名。
func GetCategoryName(category string) string {
	if name, ok := categoryNames[category]; ok {
		return name
	}
	return category
}

// GetRuleName 获取规则展示名称。
func GetRuleName(ruleID string) string {
	normalized := normalizeRuleID(ruleID)
	if name, ok := ruleNames[normalized]; ok {
		return name
	}
	return strings.TrimSpace(ruleID)
}

// GetConfidence 获取规则可信度。
func GetConfidence(ruleID string) string {
	normalized := normalizeRuleID(ruleID)
	switch normalized {
	case "path", "url", "api_endpoint", "domain", "email", "phone_cn", "id_card_cn",
		"ipv4", "internal_ip", "mac_address", "uuid", "base64_long", "md5_hash", "sha1_hash",
		"sha256_hash", "ssh_rsa_public", "ssh_ed25519_public":
		return "low"
	case "credit_card", "db_password", "db_username", "db_host", "jdbc_mysql", "jdbc_postgresql",
		"jdbc_oracle", "jdbc_sqlserver", "jdbc_db2", "mongodb_connection", "redis_connection",
		"postgres_connection", "mysql_connection":
		return "high"
	}

	switch GetCategoryKey(ruleID) {
	case "cloud", "payment", "messaging", "devops", "observability", "security", "saas", "wechat", "private_key":
		return "high"
	case "database", "password", "api_key", "secret", "token":
		return "medium"
	default:
		return "low"
	}
}

func normalizeRuleID(ruleID string) string {
	normalized := strings.ToLower(strings.TrimSpace(ruleID))
	normalized = nonAlnumPattern.ReplaceAllString(normalized, "_")
	return strings.Trim(normalized, "_")
}

func hasAnyFragment(input string, fragments ...string) bool {
	for _, fragment := range fragments {
		if fragment == "" {
			continue
		}
		if strings.Contains(input, fragment) {
			return true
		}
	}
	return false
}

func looksLikeSaaSCredential(normalized string) bool {
	if normalized == "" {
		return false
	}

	if !hasAnyFragment(normalized,
		"secret", "token", "api_key", "apikey", "access_key", "client_id",
		"client_secret", "password", "webhook", "oauth", "sid", "pat",
	) {
		return false
	}

	if hasAnyFragment(normalized,
		"generic", "path", "url", "domain", "email", "phone", "ipv4", "internal_ip",
		"mac_address", "uuid", "hash", "base64", "jdbc", "db_", "database",
	) {
		return false
	}

	return true
}
