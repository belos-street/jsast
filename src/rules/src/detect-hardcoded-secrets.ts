import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测硬编码的敏感信息规则
 *
 * 设计思路：
 * 1. 检测各种类型的硬编码敏感信息：API keys、密码、数据库连接字符串等
 * 2. 使用正则表达式匹配常见的敏感信息模式
 * 3. 避免误报：排除环境变量、空字符串、短字符串、占位符等
 * 4. 检测多种上下文：变量声明、对象属性、函数参数等
 *
 * 检测范围：
 * - API keys: sk-*, pk-*, Bearer *, API_KEY_*, etc.
 * - 密码: password, passwd, secret, token 等变量名
 * - 数据库连接字符串: mongodb://user:pass@*, postgresql://user:pass@*, etc.
 * - JWT tokens: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
 * - AWS keys: AKIAIOSFODNN7EXAMPLE, wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
 * - GitHub tokens: ghp_*, gho_*, ghu_*, ghs_*, ghr_*
 * - Slack tokens: xoxb-*, xoxp-*
 * - Stripe keys: sk_test_*, sk_live_*, pk_test_*, pk_live_*
 * - Firebase/Google keys: AIzaSy*
 * - Twilio keys: SK*
 * - SendGrid keys: SG.*
 * - Mailgun keys: key-*
 * - Datadog keys: 32位十六进制字符串
 * - New Relic keys: 40位十六进制字符串
 * - PagerDuty keys: 20位十六进制字符串
 * - Rollbar keys: 32位十六进制字符串
 * - Sentry DSN: https://*@sentry.io/*
 *
 * 安全模式（不检测）：
 * - 环境变量: process.env.API_KEY
 * - 空字符串: ''
 * - 短字符串: '123'
 * - 占位符: 'your_password_here', 'your-api-key-here'
 * - 本地URL: 'mongodb://localhost:27017/mydb'
 * - 生产URL: 'https://api.example.com'
 * - 模板字符串中的环境变量: `mongodb://${process.env.DB_USER}:${process.env.DB_PASS}@localhost`
 * - 配置文件引用: require('./config.json')
 * - 导入语句: import { apiKey } from './secrets'
 */

const SECRET_PATTERNS = [
  {
    name: 'API Key',
    patterns: [
      /\b(sk-[a-zA-Z0-9]{16,})\b/,
      /\b(pk-[a-zA-Z0-9]{16,})\b/,
      /\b(Bearer [a-zA-Z0-9]{16,})\b/,
      /\b(API_KEY_[a-zA-Z0-9]{16,})\b/,
      /\b(apikey-[a-zA-Z0-9]{16,})\b/,
      /\b(api_key-[a-zA-Z0-9]{16,})\b/
    ]
  },
  {
    name: 'JWT Token',
    patterns: [/^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/]
  },
  {
    name: 'AWS Access Key',
    patterns: [/\b(AKIA[0-9A-Z]{16,20})\b/]
  },
  {
    name: 'AWS Secret Key',
    patterns: [/\b([a-zA-Z0-9/+]{40})\b/]
  },
  {
    name: 'GitHub Token',
    patterns: [
      /\b(ghp_[a-zA-Z0-9]{20,})\b/,
      /\b(gho_[a-zA-Z0-9]{20,})\b/,
      /\b(ghu_[a-zA-Z0-9]{20,})\b/,
      /\b(ghs_[a-zA-Z0-9]{20,})\b/,
      /\b(ghr_[a-zA-Z0-9]{20,})\b/
    ]
  },
  {
    name: 'Slack Token',
    patterns: [/\b(xoxb-[0-9]{8,}-[0-9]{8,}-[a-zA-Z0-9]{20,})\b/, /\b(xoxp-[0-9]{8,}-[0-9]{8,}-[0-9]{8,}-[a-zA-Z0-9]{20,})\b/]
  },
  {
    name: 'Stripe Key',
    patterns: [
      /\b(sk_test_[a-zA-Z0-9]{24,})\b/,
      /\b(sk_live_[a-zA-Z0-9]{24,})\b/,
      /\b(pk_test_[a-zA-Z0-9]{24,})\b/,
      /\b(pk_live_[a-zA-Z0-9]{24,})\b/
    ]
  },
  {
    name: 'Firebase/Google Key',
    patterns: [/\b(AIzaSy[a-zA-Z0-9_-]{33})\b/]
  },
  {
    name: 'Twilio Key',
    patterns: [/\b(SK[a-f0-9]{32})\b/]
  },
  {
    name: 'SendGrid Key',
    patterns: [/\b(SG\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{40,})\b/]
  },
  {
    name: 'Mailgun Key',
    patterns: [/\b(key-[a-zA-Z0-9]{32})\b/]
  },
  {
    name: 'Datadog Key',
    patterns: [/\b([a-f0-9]{32})\b/]
  },
  {
    name: 'New Relic Key',
    patterns: [/\b([a-f0-9]{40})\b/]
  },
  {
    name: 'PagerDuty Key',
    patterns: [/\b([a-f0-9]{20})\b/]
  },
  {
    name: 'Rollbar Key',
    patterns: [/\b([a-f0-9]{32})\b/]
  },
  {
    name: 'Sentry DSN',
    patterns: [/\b(https:\/\/[a-zA-Z0-9_-]+@sentry\.io\/[0-9]+)\b/]
  },
  {
    name: 'Database URL',
    patterns: [
      /\b(mongodb:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(postgresql:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(mysql:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(redis:\/\/:[^@]+@)/,
      /\b(http:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(https:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(ftp:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(sftp:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(smtp:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(imap:\/\/[a-zA-Z0-9_-]+:[^@]+@)/,
      /\b(pop3:\/\/[a-zA-Z0-9_-]+:[^@]+@)/
    ]
  }
]

const PLACEHOLDER_PATTERNS = [
  /^your_password_here$/i,
  /^your-api-key-here$/i,
  /^your_secret_here$/i,
  /^your_token_here$/i,
  /^placeholder$/i,
  /^demo$/i,
  /^sample$/i,
  /^xxx$/i,
  /^yyy$/i,
  /^zzz$/i
]

const ENV_VAR_PATTERNS = [/process\.env\./, /\$\{.*\}/, /env\./]

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(value))
}

function isEnvironmentVariable(value: string): boolean {
  return ENV_VAR_PATTERNS.some((pattern) => pattern.test(value))
}

function isTooShort(value: string): boolean {
  return value.length < 4
}

function isEmpty(value: string): boolean {
  return value.length === 0
}

function containsSecret(value: string): { found: boolean; type: string } {
  for (const secret of SECRET_PATTERNS) {
    for (const pattern of secret.patterns) {
      if (pattern.test(value)) {
        return { found: true, type: secret.name }
      }
    }
  }
  return { found: false, type: '' }
}

export const detectHardcodedSecretsRule: Rule = {
  name: 'detect-hardcoded-secrets',
  description: 'Detect hardcoded secrets and sensitive information',
  severity: 'error',
  category: 'hardcoded-secrets',
  check(node) {
    const issues: RuleIssue[] = []

    if (!node.loc) return issues

    const checkStringLiteral = (literal: { value: string }) => {
      const value = literal.value

      if (isEmpty(value) || isTooShort(value) || isPlaceholder(value) || isEnvironmentVariable(value)) {
        return
      }

      const secretResult = containsSecret(value)
      if (secretResult.found) {
        issues.push({
          message: `Hardcoded ${secretResult.type} detected: ${value.substring(0, 10)}... Use environment variables instead`,
          line: node.loc!.start.line!,
          column: node.loc!.start.column!
        })
      }
    }

    if (node.type === 'StringLiteral') {
      checkStringLiteral(node)
    } else if (node.type === 'TemplateLiteral') {
      for (const quasi of node.quasis) {
        checkStringLiteral({ value: quasi.value.cooked || '' })
      }
    }

    return issues
  }
}
