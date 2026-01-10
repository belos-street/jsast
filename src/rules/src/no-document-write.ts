import type { Expression, SpreadElement } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用document.write规则
 *
 * 设计思路：
 * 1. 检测 document.write 和 document.writeln 的使用
 * 2. 支持多种调用模式：直接调用、变量引用
 * 3. 忽略安全的静态字符串调用
 *
 * 检测范围：
 * - document.write(userInput): 变量参数
 * - document.write('<div>' + userInput + '</div>'): 字符串拼接
 * - document.write(`<div>${userInput}</div>`): 模板字符串
 * - document.write(getHtml()): 函数调用
 * - document.writeln(userInput): writeln 方法
 *
 * 安全模式（不检测）：
 * - 静态字符串：document.write('<div>Static content</div>')
 * - 纯文本：document.write('Hello World')
 */
export const noDocumentWriteRule: Rule = {
  name: 'no-document-write',
  description: 'Avoid using document.write or document.writeln with untrusted input',
  severity: 'warning',
  category: 'xss',
  check(node) {
    const issues: RuleIssue[] = []

    if (!node.loc) {
      return issues
    }

    const hasDynamicContent = (arg: Expression | SpreadElement): boolean => {
      if (arg.type === 'SpreadElement') {
        return false
      }
      if (arg.type === 'TemplateLiteral') {
        return arg.expressions.length > 0
      }
      if (arg.type === 'BinaryExpression') {
        return true
      }
      if (arg.type === 'Identifier') {
        return true
      }
      if (arg.type === 'CallExpression') {
        return true
      }
      if (arg.type === 'MemberExpression') {
        return true
      }
      if (arg.type === 'ObjectExpression') {
        return true
      }
      return false
    }

    if (node.type === 'CallExpression') {
      const callee = node.callee

      if (callee.type === 'MemberExpression') {
        const object = callee.object

        if (object.type === 'Identifier' && object.name === 'document') {
          const property = callee.property

          if (property.type === 'Identifier') {
            const methodName = property.name

            if (methodName === 'write' || methodName === 'writeln') {
              const firstArg = node.arguments[0] as Expression | SpreadElement | undefined

              if (firstArg && hasDynamicContent(firstArg)) {
                issues.push({
                  line: node.loc.start.line,
                  column: node.loc.start.column,
                  message: `Avoid using document.${methodName} with untrusted input. This may lead to XSS vulnerabilities. Use DOM manipulation methods like createElement and appendChild instead.`
                })
              }
            }
          }
        }
      }
    }

    return issues
  }
}
