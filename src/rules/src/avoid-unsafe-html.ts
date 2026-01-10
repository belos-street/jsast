import type { Expression, JSXElement, PrivateName } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 不安全的HTML生成检测规则
 *
 * 设计思路：
 * 1. 检测 Express res.send 调用中包含动态 HTML 内容的情况
 * 2. 检测 React JSX 中未转义的变量内容（可能导致 XSS）
 * 3. 检测其他不安全的 HTML 生成方法（document.write、outerHTML、insertAdjacentHTML）
 * 4. 忽略安全的静态字符串和纯文本内容
 *
 * 检测范围：
 * - Express res.send：`res.send('<div>' + userInput + '</div>')`
 * - React JSX：`<div>{userInput}</div>` (未转义内容)
 * - document.write：`document.write('<div>' + userInput + '</div>')`
 * - outerHTML：`element.outerHTML = '<div>' + userInput + '</div>'`
 * - insertAdjacentHTML：`element.insertAdjacentHTML('beforeend', '<div>' + userInput + '</div>')`
 *
 * 安全模式（不检测）：
 * - 静态 HTML：`res.send('<div>Static content</div>')`
 * - 纯文本：`res.send('Hello World')`
 * - JSX 静态内容：`<div>Static content</div>`
 * - JSX 数字/布尔值：`<div>{count}</div>`, `<div>{isActive ? 'Active' : 'Inactive'}</div>`
 */
export const avoidUnsafeHtmlRule: Rule = {
  name: 'avoid-unsafe-html',
  description: 'Avoid generating HTML with untrusted input',
  severity: 'warning',
  category: 'xss',
  check(node) {
    const issues: RuleIssue[] = []

    if (!node.loc) {
      return issues
    }

    const hasDynamicContent = (arg: Expression): boolean => {
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

    const containsHtmlTags = (str: string): boolean => {
      return /<[a-zA-Z][^>]*>/.test(str)
    }

    const isHtmlString = (arg: Expression | PrivateName): boolean => {
      if (arg.type === 'StringLiteral') {
        return containsHtmlTags(arg.value)
      }
      if (arg.type === 'TemplateLiteral') {
        for (const quasi of arg.quasis) {
          if (containsHtmlTags(quasi.value.cooked || quasi.value.raw)) {
            return true
          }
        }
      }
      if (arg.type === 'BinaryExpression') {
        return isHtmlString(arg.left) || isHtmlString(arg.right)
      }
      return false
    }

    const mightContainHtml = (arg: Expression): boolean => {
      if (arg.type === 'Identifier' || arg.type === 'CallExpression' || arg.type === 'MemberExpression') {
        return true
      }
      return isHtmlString(arg)
    }

    if (node.type === 'CallExpression') {
      const callee = node.callee

      if (callee.type === 'MemberExpression') {
        const object = callee.object
        const property = callee.property

        if (property.type === 'Identifier') {
          const propName = property.name

          if (propName === 'send' && object.type === 'Identifier' && object.name === 'res') {
            const args = node.arguments
            if (args.length > 0) {
              const firstArg = args[0] as Expression
              if (hasDynamicContent(firstArg) && mightContainHtml(firstArg)) {
                issues.push({
                  line: node.loc.start.line,
                  column: node.loc.start.column,
                  message: 'Avoid using res.send with dynamic HTML content. This may lead to XSS vulnerabilities.'
                })
              }
            }
          }

          if (propName === 'write' && object.type === 'Identifier' && object.name === 'document') {
            const args = node.arguments
            if (args.length > 0) {
              const firstArg = args[0] as Expression
              if (hasDynamicContent(firstArg) && isHtmlString(firstArg)) {
                issues.push({
                  line: node.loc.start.line,
                  column: node.loc.start.column,
                  message: 'Avoid using document.write with dynamic HTML content. This may lead to XSS vulnerabilities.'
                })
              }
            }
          }

          if (propName === 'insertAdjacentHTML') {
            const args = node.arguments
            if (args.length > 1) {
              const secondArg = args[1] as Expression
              if (hasDynamicContent(secondArg) && isHtmlString(secondArg)) {
                issues.push({
                  line: node.loc.start.line,
                  column: node.loc.start.column,
                  message: 'Avoid using insertAdjacentHTML with dynamic HTML content. This may lead to XSS vulnerabilities.'
                })
              }
            }
          }
        }
      }
    }

    if (node.type === 'AssignmentExpression') {
      const left = node.left
      const right = node.right

      if (left.type === 'MemberExpression') {
        const property = left.property
        if (property.type === 'Identifier' && property.name === 'outerHTML') {
          if (hasDynamicContent(right) && isHtmlString(right)) {
            issues.push({
              line: node.loc.start.line,
              column: node.loc.start.column,
              message: 'Avoid assigning dynamic HTML to outerHTML. This may lead to XSS vulnerabilities.'
            })
          }
        }
      }
    }

    if (node.type === 'JSXElement') {
      const checkJsxContent = (jsxNode: JSXElement) => {
        for (const child of jsxNode.children) {
          if (child.type === 'JSXElement') {
            checkJsxContent(child)
          } else if (child.type === 'JSXExpressionContainer') {
            const expression = child.expression
            const isSafeExpression =
              expression.type === 'NumericLiteral' ||
              expression.type === 'BooleanLiteral' ||
              expression.type === 'NullLiteral' ||
              expression.type === 'BigIntLiteral' ||
              (expression.type === 'ConditionalExpression' &&
                expression.consequent.type === 'StringLiteral' &&
                expression.alternate.type === 'StringLiteral')
            if (!isSafeExpression) {
              if (
                expression.type === 'Identifier' ||
                expression.type === 'MemberExpression' ||
                expression.type === 'CallExpression'
              ) {
                issues.push({
                  line: child.loc!.start.line,
                  column: child.loc!.start.column,
                  message: 'Avoid rendering untrusted input in JSX without proper escaping. This may lead to XSS vulnerabilities.'
                })
              } else if (expression.type === 'TemplateLiteral' && expression.expressions.length > 0) {
                issues.push({
                  line: child.loc!.start.line,
                  column: child.loc!.start.column,
                  message: 'Avoid rendering untrusted input in JSX without proper escaping. This may lead to XSS vulnerabilities.'
                })
              }
            }
          }
        }
      }
      checkJsxContent(node)
    }

    return issues
  }
}
