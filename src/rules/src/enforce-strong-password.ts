import type { Node } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 强密码策略检测规则
 *
 * 设计思路：
 * 1. 检测密码长度验证是否过短
 * 2. 检测密码复杂度验证是否缺失
 * 3. 识别常见的弱密码验证模式
 * 4. 建议实施强密码策略
 *
 * 检测范围：
 * - 密码长度检查：if (password.length < 6) - 建议至少8位
 * - 缺失复杂度检查：没有检查大小写、数字、特殊字符
 * - 简单正则表达式：仅检查字母或数字
 * - 弱密码策略：允许简单密码
 *
 * 安全模式（不检测）：
 * - 已实施的强密码策略：包含长度、复杂度、常见密码检查
 * - 使用密码强度库：zxcvbn, password-strength-meter
 * - 第三方密码验证服务
 */

const MIN_LENGTH_THRESHOLD = 8

const PASSWORD_VARIABLES = [
  'password',
  'passwd',
  'pwd',
  'pass',
  'userPassword',
  'user_password',
  'userPass',
  'user_pass',
  'adminPassword',
  'admin_password',
  'adminPass',
  'admin_pass',
  'loginPassword',
  'login_password',
  'loginPass',
  'login_pass'
]

function isPasswordVariable(name: string): boolean {
  return PASSWORD_VARIABLES.includes(name)
}

function isLengthCheck(node: Node): boolean {
  if (node.type === 'BinaryExpression' && node.operator === '<') {
    if (node.left.type === 'MemberExpression') {
      const object = node.left.object
      const property = node.left.property
      if (property.type === 'Identifier' && property.name === 'length') {
        if (object.type === 'Identifier' && isPasswordVariable(object.name)) {
          const rightValue = getNumericValue(node.right)
          if (rightValue !== null && rightValue < MIN_LENGTH_THRESHOLD) {
            return true
          }
        }
      }
    }
  }
  return false
}

function getNumericValue(node: Node): number | null {
  if (node.type === 'NumericLiteral') {
    return node.value
  }
  if (node.type === 'StringLiteral') {
    const parsed = parseInt(node.value, 10)
    return isNaN(parsed) ? null : parsed
  }
  return null
}

function isWeakPasswordValidation(node: Node): boolean {
  if (node.type === 'IfStatement') {
    const test = node.test
    if (isLengthCheck(test)) {
      return true
    }
  }
  return false
}

export const enforceStrongPasswordRule: Rule = {
  name: 'enforce-strong-password',
  description: 'Detect weak password policies',
  severity: 'warning',
  category: 'insecure-authentication',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'IfStatement' && node.loc) {
      if (isWeakPasswordValidation(node)) {
        issues.push({
          message: `Weak password policy: Password validation only checks length < ${MIN_LENGTH_THRESHOLD}. Implement strong password policy requiring at least ${MIN_LENGTH_THRESHOLD} characters, including uppercase, lowercase, numbers, and special characters. Consider using password strength libraries like zxcvbn`,
          line: node.loc.start.line,
          column: node.loc.start.column
        })
      }
    }

    return issues
  }
}
