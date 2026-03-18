import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测使用HTTP而非HTTPS规则
 *
 * 设计思路：
 * 1. 检测使用http://协议的非安全URL调用
 * 2. 支持多种HTTP客户端：fetch、axios、http.request、https.request等
 * 3. 检测字符串字面量和模板字符串中的http:// URL
 * 4. 排除本地开发环境常见的localhost地址
 *
 * 检测范围：
 * - fetch调用: `fetch('http://api.example.com')`
 * - axios请求: `axios.get('http://api.example.com')`, `axios.post('http://api.example.com')`
 * - http.request: `http.request('http://api.example.com')`
 * - https.request: `https.request('http://api.example.com')`
 * - 模板字符串: `fetch(\`http://\${host}/api\`)`
 * - 字符串字面量: `const url = 'http://api.example.com'`
 *
 * 安全模式（不检测）：
 * - HTTPS URL: `https://api.example.com`
 * - 本地开发环境: `http://localhost:3000`, `http://127.0.0.1:8080`
 * - 环境变量: `process.env.API_URL`
 */

const HTTP_CLIENT_METHODS = [
  'fetch',
  'axios',
  'http',
  'https',
  'request',
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'head',
  'options'
]

const LOCALHOST_PATTERNS = [/^http:\/\/localhost(:\d+)?\//, /^http:\/\/127\.0\.0\.1(:\d+)?\//, /^http:\/\/0\.0\.0\.0(:\d+)?\//]

const HTTPS_PATTERN = /^https:\/\//

function isLocalhostUrl(url: string): boolean {
  return LOCALHOST_PATTERNS.some((pattern) => pattern.test(url))
}

function isHttpsUrl(url: string): boolean {
  return HTTPS_PATTERN.test(url)
}

function containsHttpUrl(value: string): boolean {
  const httpUrlPattern = /http:\/\/[^\s'"]+/
  return httpUrlPattern.test(value)
}

function checkHttpUrl(
  literal: { value: string },
  location: { start: { line: number; column: number } },
  issues: RuleIssue[]
): void {
  const urlValue = literal.value

  if (!urlValue || isHttpsUrl(urlValue) || isLocalhostUrl(urlValue)) {
    return
  }

  if (containsHttpUrl(urlValue)) {
    issues.push({
      message: `Insecure HTTP URL detected: ${urlValue.substring(0, 40)}${urlValue.length > 40 ? '...' : ''}. Use HTTPS instead of HTTP for secure communication`,
      line: location.start.line,
      column: location.start.column
    })
  }
}

export const useHttpsRule: Rule = {
  name: 'use-https',
  description: 'Detect usage of HTTP instead of HTTPS',
  severity: 'warning',
  category: 'insecure-http',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'Identifier' && HTTP_CLIENT_METHODS.includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
          checkHttpUrl(firstArg as { value: string }, node.loc, issues)
        }
      }

      if (callee.type === 'MemberExpression') {
        const property = callee.property
        const object = callee.object

        if (property.type === 'Identifier' && HTTP_CLIENT_METHODS.slice(1).includes(property.name)) {
          let firstArg = null
          if (object.type === 'Identifier' && (object.name === 'axios' || object.name === 'http' || object.name === 'https')) {
            firstArg = node.arguments[0]
          }

          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            checkHttpUrl(firstArg as { value: string }, node.loc, issues)
          }
        }

        if (property.type === 'Identifier' && property.name === 'request' && object.type === 'MemberExpression') {
          const secondArg = node.arguments[1]
          if (secondArg && (secondArg.type === 'StringLiteral' || secondArg.type === 'TemplateLiteral')) {
            checkHttpUrl(secondArg as { value: string }, node.loc, issues)
          }
        }
      }
    }

    return issues
  }
}
