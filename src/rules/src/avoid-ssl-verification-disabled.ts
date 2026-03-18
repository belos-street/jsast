import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测禁用SSL验证规则
 *
 * 设计思路：
 * 1. 检测各种禁用SSL/TLS验证的模式
 * 2. 支持多种HTTP库和配置方式
 * 3. 识别赋值表达式和属性访问模式
 *
 * 检测范围：
 * - https.globalAgent.options.rejectUnauthorized = false
 * - https.globalAgent.options.rejectUnauthorized = '0'
 * - process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
 * - process.env.NODE_TLS_REJECT_UNAUTHORIZED = 'false'
 * - agent.options.rejectUnauthorized = false
 * - axios请求中设置rejectUnauthorized: false
 * - fetch请求中设置secure: false
 *
 * 安全模式（不检测）：
 * - 启用SSL验证的正常配置
 * - 环境变量设置为非零值
 */

const INSECURE_PATTERNS = [
  {
    pattern: /^process\.env\.NODE_TLS_REJECT_UNAUTHORIZED$/,
    valuePattern: /^('|")?(0|false)('|")?$/i,
    message:
      'Insecure TLS configuration: NODE_TLS_REJECT_UNAUTHORIZED is set to disabled, which disables SSL/TLS certificate verification and exposes the application to man-in-the-middle attacks'
  },
  {
    pattern: /rejectUnauthorized/,
    valuePattern: /^('|")?(0|false)('|")?$/i,
    message:
      'Insecure TLS configuration: rejectUnauthorized is set to false, which disables SSL/TLS certificate verification and exposes the application to man-in-the-middle attacks'
  },
  {
    pattern: /^secure$/,
    valuePattern: /^('|")?(0|false)('|")?$/i,
    message:
      'Insecure TLS configuration: secure option is set to false, which disables SSL/TLS certificate verification and exposes the application to man-in-the-middle attacks'
  }
]

function matchesInsecurePattern(leftSide: string, rightValue: string): string | null {
  for (const item of INSECURE_PATTERNS) {
    if (item.pattern.test(leftSide) && item.valuePattern.test(rightValue.trim())) {
      return item.message
    }
  }
  return null
}

type MemberExpressionNode = {
  type: 'MemberExpression' | 'OptionalMemberExpression'
  object: MemberExpressionNode | { type: 'Identifier'; name: string }
  property: { type: 'Identifier'; name: string }
}

function getLeftSideString(node: MemberExpressionNode | { type: 'Identifier'; name: string }): string {
  if (node.type === 'Identifier') {
    return node.name
  }
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const object = getLeftSideString(node.object as MemberExpressionNode | { type: 'Identifier'; name: string })
    const property = node.property.type === 'Identifier' ? node.property.name : ''
    return `${object}.${property}`
  }
  return ''
}

type ExpressionNode = {
  type: 'Identifier' | 'StringLiteral' | 'NumericLiteral' | 'BooleanLiteral' | 'UnaryExpression'
  name?: string
  value?: string | number | boolean
  operator?: string
  argument?: ExpressionNode
}

function getValueString(node: ExpressionNode): string {
  if (node.type === 'Identifier') {
    return node.name || ''
  }
  if (node.type === 'StringLiteral') {
    return (node.value as string) || ''
  }
  if (node.type === 'NumericLiteral') {
    return String(node.value)
  }
  if (node.type === 'BooleanLiteral') {
    return String(node.value)
  }
  if (node.type === 'UnaryExpression' && node.operator === '!') {
    return '!' + getValueString(node.argument as ExpressionNode)
  }
  if (node.type === 'UnaryExpression' && node.operator === '-' && (node.argument as ExpressionNode).type === 'NumericLiteral') {
    return '-' + String((node.argument as { type: 'NumericLiteral'; value: number }).value)
  }
  return ''
}

export const avoidSslVerificationDisabledRule: Rule = {
  name: 'avoid-ssl-verification-disabled',
  description: 'Detect disabled SSL verification',
  severity: 'error',
  category: 'insecure-http',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'AssignmentExpression' && node.loc) {
      const left = node.left
      if (left.type !== 'MemberExpression' && left.type !== 'Identifier' && left.type !== 'OptionalMemberExpression') {
        return issues
      }
      const leftSide = getLeftSideString(left as MemberExpressionNode | { type: 'Identifier'; name: string })
      const rightValue = getValueString(node.right as ExpressionNode)

      if (leftSide && rightValue) {
        const message = matchesInsecurePattern(leftSide, rightValue)
        if (message) {
          issues.push({
            message,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    if (node.type === 'ObjectProperty' && node.loc) {
      const keyName = node.key.type === 'Identifier' ? node.key.name : ''
      const value = node.value
      let valueString = ''

      if (value.type === 'BooleanLiteral') {
        valueString = String(value.value)
      } else if (value.type === 'StringLiteral') {
        valueString = value.value
      } else if (value.type === 'NumericLiteral') {
        valueString = String(value.value)
      } else if (value.type === 'Identifier') {
        valueString = value.name
      }

      if (keyName === 'rejectUnauthorized' || keyName === 'secure') {
        if (valueString === 'false' || valueString === '0') {
          issues.push({
            message: `Insecure TLS configuration: ${keyName} is set to ${valueString}, which disables SSL/TLS certificate verification and exposes the application to man-in-the-middle attacks`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    return issues
  }
}
