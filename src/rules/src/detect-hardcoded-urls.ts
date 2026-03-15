import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测硬编码URL规则
 *
 * 设计思路：
 * 1. 检测各种类型的硬编码URL：HTTP/HTTPS、WebSocket、FTP、数据库连接等
 * 2. 使用正则表达式匹配常见的URL模式
 * 3. 避免误报：排除环境变量、空字符串、短字符串、占位符、特殊协议等
 * 4. 检测多种上下文：变量声明、对象属性、函数参数等
 *
 * 检测范围：
 * - HTTP/HTTPS URL: `https://api.example.com`, `http://localhost:3000`
 * - WebSocket URL: `ws://example.com/socket`, `wss://example.com/socket`
 * - FTP/SFTP URL: `ftp://example.com/files`, `sftp://example.com/files`
 * - 数据库URL: `mongodb://localhost:27017/mydb`, `redis://localhost:6379`
 * - 包含端口、路径、查询参数的URL
 *
 * 安全模式（不检测）：
 * - 环境变量: `process.env.API_URL`, `${process.env.API_URL}`
 * - 空字符串: `''`
 * - 短字符串: `'http'`
 * - 相对路径: `'/api/users'`
 * - 特殊协议: `file://`, `data:`, `mailto:`, `tel:`, `javascript:`, `about:`
 * - 占位符: `'your-api-url-here'`, `'placeholder'`
 */

const URL_PATTERNS = [
  {
    name: 'URL',
    patterns: [
      /^https?:\/\/[^\s]+/,
      /^wss?:\/\/[^\s]+/,
      /^ftps?:\/\/[^\s]+/,
      /^sftp:\/\/[^\s]+/,
      /^mongodb:\/\/[^\s]+/,
      /^redis:\/\/[^\s]+/,
      /^postgres:\/\/[^\s]+/,
      /^mysql:\/\/[^\s]+/,
      /^sqlite:\/\/[^\s]+/,
      /^elasticsearch:\/\/[^\s]+/
    ]
  }
]

const EXCLUDED_PROTOCOLS = ['file://', 'data:', 'mailto:', 'tel:', 'javascript:', 'about:']

const PLACEHOLDER_PATTERNS = [
  /^your-api-url-here$/i,
  /^your-url-here$/i,
  /^your-endpoint-here$/i,
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
  return value.length < 8
}

function isEmpty(value: string): boolean {
  return value.length === 0
}

function isExcludedProtocol(value: string): boolean {
  return EXCLUDED_PROTOCOLS.some((protocol) => value.startsWith(protocol))
}

function isRelativePath(value: string): boolean {
  return value.startsWith('/') || value.startsWith('./') || value.startsWith('../')
}

function containsUrl(value: string): { found: boolean; type: string } {
  for (const url of URL_PATTERNS) {
    for (const pattern of url.patterns) {
      if (pattern.test(value)) {
        return { found: true, type: url.name }
      }
    }
  }

  const urlPatterns = [
    /https?:\/\/[^\s]+/,
    /wss?:\/\/[^\s]+/,
    /ftps?:\/\/[^\s]+/,
    /sftp:\/\/[^\s]+/,
    /mongodb:\/\/[^\s]+/,
    /redis:\/\/[^\s]+/,
    /postgres:\/\/[^\s]+/,
    /mysql:\/\/[^\s]+/,
    /sqlite:\/\/[^\s]+/,
    /elasticsearch:\/\/[^\s]+/
  ]

  for (const pattern of urlPatterns) {
    if (pattern.test(value)) {
      return { found: true, type: 'URL' }
    }
  }

  return { found: false, type: '' }
}

export const detectHardcodedUrlsRule: Rule = {
  name: 'detect-hardcoded-urls',
  description: 'Detect hardcoded URLs and endpoints',
  severity: 'warning',
  category: 'hardcoded-secrets',
  check(node) {
    const issues: RuleIssue[] = []

    if (!node.loc) return issues

    const checkStringLiteral = (literal: { value: string }) => {
      const value = literal.value

      if (isEmpty(value) || isTooShort(value) || isPlaceholder(value) || isEnvironmentVariable(value)) {
        return
      }

      if (isExcludedProtocol(value) || isRelativePath(value)) {
        return
      }

      const urlResult = containsUrl(value)
      if (urlResult.found) {
        issues.push({
          message: `hardcoded ${urlResult.type} detected: ${value.substring(0, 30)}... Use environment variables or configuration files instead`,
          line: node.loc!.start.line,
          column: node.loc!.start.column
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
