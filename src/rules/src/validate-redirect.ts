import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测不安全的重定向规则
 *
 * 设计思路：
 * 1. 检测各种可能导致开放重定向漏洞的模式
 * 2. 支持多种框架和库的重定向方法
 * 3. 识别动态重定向目标（用户输入、变量、函数调用）
 *
 * 检测范围：
 * - Express: res.redirect(userInput), res.redirect(url + query)
 * - Koa: ctx.redirect(url), ctx.redirect(userInput)
 * - React: window.location.href = userInput, window.location.replace(userInput)
 * - 标准: location.href = userInput, location.replace(userInput)
 * - Fetch/axios重定向配置中的不安全URL
 *
 * 安全模式（不检测）：
 * - 静态白名单URL: res.redirect('/home'), res.redirect('/login')
 * - 已验证的URL: 只有在验证后才进行重定向
 * - 协议限制: 只允许 https:// 或相对于当前站点的路径
 * - 环境变量: process.env.REDIRECT_URL (假设已验证)
 */

const REDIRECT_METHODS = [
  'redirect',
  'replace',
  'href',
  'window.location.replace',
  'window.location.href',
  'location.replace',
  'location.href',
  'navigateTo',
  'pushState',
  'replaceState'
]

const DANGEROUS_PATTERNS = [/^(http|https):\/\//, /\/\.\./, /\.\./, /javascript:/i, /data:/i]

function isStaticWhitelistPath(value: string): boolean {
  const whitelistPatterns = [/^\/[a-zA-Z0-9_/-]*$/, /^https?:\/\/localhost(:\d+)?\//, /^https?:\/\/127\.0\.0\.1(:\d+)?\//]
  return whitelistPatterns.some((pattern) => pattern.test(value))
}

function containsDangerousPattern(value: string): boolean {
  return DANGEROUS_PATTERNS.some((pattern) => pattern.test(value))
}

function isLocalhostUrl(value: string): boolean {
  const localhostPattern = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?\//
  return localhostPattern.test(value)
}

function containsEnvironmentVariable(node: any): boolean {
  if (!node) return false
  if (node.type === 'MemberExpression') {
    if (
      node.object.type === 'Identifier' &&
      node.object.name === 'process' &&
      node.property.type === 'Identifier' &&
      node.property.name === 'env'
    ) {
      return true
    }
    return containsEnvironmentVariable(node.object) || containsEnvironmentVariable(node.property)
  }
  if (node.type === 'BinaryExpression') {
    return containsEnvironmentVariable(node.left) || containsEnvironmentVariable(node.right)
  }
  if (node.type === 'TemplateLiteral' && node.expressions) {
    return node.expressions.some((expr: any) => containsEnvironmentVariable(expr))
  }
  return false
}

function startsWithPathSlash(value: string): boolean {
  return value.startsWith('/') && !value.startsWith('//') && !value.startsWith('https://') && !value.startsWith('http://')
}

function containsLeadingSlash(node: any): boolean {
  if (node.type === 'StringLiteral' && startsWithPathSlash(node.value)) {
    return true
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return containsLeadingSlash(node.left) || containsLeadingSlash(node.right)
  }
  return false
}

function isUnsafeRedirectExpression(node: any): boolean {
  if (!isDynamicExpression(node)) {
    return false
  }
  if (containsLeadingSlash(node)) {
    return true
  }
  if (containsEnvironmentVariable(node)) {
    return false
  }
  return true
}

function isSafeRedirect(node: any, value: string): boolean {
  if (!value) return true
  if (containsEnvironmentVariable(node)) return true
  if (isStaticWhitelistPath(value)) return true
  if (isLocalhostUrl(value)) return true
  return false
}

function getStringValue(node: any): string {
  if (node.type === 'StringLiteral') {
    return node.value
  }
  if (node.type === 'TemplateLiteral' && node.quasis && node.quasis.length > 0) {
    return node.quasis.map((quasi: any) => quasi.value.raw).join('')
  }
  if (node.type === 'BinaryExpression') {
    return getStringValue(node.left) + '+' + getStringValue(node.right)
  }
  return ''
}

function isDynamicExpression(node: any): boolean {
  if (node.type === 'Identifier') {
    return true
  }
  if (node.type === 'MemberExpression') {
    return true
  }
  if (node.type === 'CallExpression') {
    return true
  }
  if (node.type === 'BinaryExpression') {
    return isDynamicExpression(node.left) || isDynamicExpression(node.right)
  }
  if (node.type === 'TemplateLiteral' && node.expressions && node.expressions.length > 0) {
    return true
  }
  return false
}

export const validateRedirectRule: Rule = {
  name: 'validate-redirect',
  description: 'Detect unsafe redirect',
  severity: 'warning',
  category: 'insecure-http',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'MemberExpression') {
        const object = callee.object
        const property = callee.property

        if (property.type === 'Identifier' && property.name === 'redirect') {
          const firstArg = node.arguments[0]
          if (firstArg) {
            const argValue = getStringValue(firstArg)
            if (argValue && !isSafeRedirect(firstArg, argValue) && containsDangerousPattern(argValue)) {
              issues.push({
                message: `Unsafe redirect: redirect uses unvalidated user input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            } else if (isUnsafeRedirectExpression(firstArg)) {
              issues.push({
                message: `Unsafe redirect: redirect uses dynamic input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }
          }
        }

        if (
          property.type === 'Identifier' &&
          (property.name === 'href' || property.name === 'replace' || property.name === 'assign')
        ) {
          let isWindowLocation = false
          if (object.type === 'MemberExpression') {
            if (
              object.object.type === 'Identifier' &&
              object.object.name === 'window' &&
              object.property.type === 'Identifier' &&
              object.property.name === 'location'
            ) {
              isWindowLocation = true
            }
          } else if (object.type === 'Identifier' && object.name === 'location') {
            isWindowLocation = true
          }

          if (isWindowLocation) {
            const firstArg = node.arguments[0]
            if (firstArg) {
              const argValue = getStringValue(firstArg)
              if (argValue && !isSafeRedirect(firstArg, argValue) && containsDangerousPattern(argValue)) {
                issues.push({
                  message: `Unsafe redirect: location.${property.name} uses unvalidated user input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
                  line: node.loc.start.line,
                  column: node.loc.start.column
                })
              } else if (isUnsafeRedirectExpression(firstArg)) {
                issues.push({
                  message: `Unsafe redirect: location.${property.name} uses dynamic input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
                  line: node.loc.start.line,
                  column: node.loc.start.column
                })
              }
            }
          }
        }
      }

      if (callee.type === 'Identifier' && REDIRECT_METHODS.includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && isDynamicExpression(firstArg)) {
          issues.push({
            message: `Unsafe redirect: ${callee.name} uses dynamic input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    if (node.type === 'AssignmentExpression' && node.loc) {
      const left = node.left
      const right = node.right

      let isLocationAssignment = false
      let assignmentType = ''

      if (left.type === 'MemberExpression') {
        const obj = left.object
        const prop = left.property
        if (prop.type === 'Identifier' && (prop.name === 'href' || prop.name === 'replace')) {
          if (
            obj.type === 'MemberExpression' &&
            obj.object.type === 'Identifier' &&
            obj.object.name === 'window' &&
            obj.property.type === 'Identifier' &&
            obj.property.name === 'location'
          ) {
            isLocationAssignment = true
            assignmentType = `window.location.${prop.name}`
          } else if (obj.type === 'Identifier' && obj.name === 'location') {
            isLocationAssignment = true
            assignmentType = `location.${prop.name}`
          }
        }
      }

      if (isLocationAssignment) {
        const rightValue = getStringValue(right)
        if (rightValue && !isSafeRedirect(right, rightValue) && containsDangerousPattern(rightValue)) {
          issues.push({
            message: `Unsafe redirect: ${assignmentType} assignment uses unvalidated user input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        } else if (isUnsafeRedirectExpression(right)) {
          issues.push({
            message: `Unsafe redirect: ${assignmentType} assignment uses dynamic input which may lead to open redirect vulnerability. Validate and whitelist redirect URLs before using them`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    return issues
  }
}
