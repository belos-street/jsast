import type { Expression, SpreadElement } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 不安全的innerHTML赋值检测规则
 *
 * 设计思路：
 * 1. 检测直接使用 innerHTML 属性赋值，包括变量、模板字符串和字符串拼接
 * 2. 检测 React 中使用 dangerouslySetInnerHTML 属性的情况
 * 3. 支持多种 DOM 操作方式：getElementById、querySelector、直接引用
 * 4. 忽略安全的静态字符串赋值和 textContent/innerText 赋值
 *
 * 检测范围：
 * - innerHTML 赋值：`element.innerHTML = userInput`
 * - 模板字符串：`element.innerHTML = \`<div>${userInput}</div>\``
 * - 字符串拼接：`element.innerHTML = "<div>" + userInput + "</div>"`
 * - React dangerouslySetInnerHTML：`<div dangerouslySetInnerHTML={{ __html: userInput }} />`
 *
 * 安全模式（不检测）：
 * - 静态字符串：`element.innerHTML = "<div>Static content</div>"`
 * - textContent 赋值：`element.textContent = userInput`
 * - innerText 赋值：`element.innerText = userInput`
 */
export const avoidDangerouslySetInnerHtmlRule: Rule = {
  name: 'avoid-dangerously-set-innerhtml',
  description: 'Avoid using innerHTML or dangerouslySetInnerHTML with untrusted input',
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

    const checkInnerHTMLAssignment = (object: Expression, value: Expression) => {
      if (hasDynamicContent(value)) {
        issues.push({
          message:
            'Unsafe innerHTML assignment: Using innerHTML with untrusted input can lead to XSS attacks. Consider using textContent, innerText, or a sanitization library like DOMPurify',
          line: node.loc!.start.line,
          column: node.loc!.start.column
        })
      }
    }

    if (node.type === 'AssignmentExpression') {
      const left = node.left
      const right = node.right

      if (left.type === 'MemberExpression' && left.property.type === 'Identifier') {
        const propertyName = left.property.name

        if (propertyName === 'innerHTML') {
          checkInnerHTMLAssignment(left.object, right)
        }
      }
    }

    if (node.type === 'JSXAttribute') {
      if (node.name.type === 'JSXIdentifier' && node.name.name === 'dangerouslySetInnerHTML') {
        if (node.value && node.value.type === 'JSXExpressionContainer') {
          const expression = node.value.expression

          if (expression.type === 'ObjectExpression') {
            const htmlProperty = expression.properties.find(
              (prop) => prop.type === 'ObjectProperty' && prop.key.type === 'Identifier' && prop.key.name === '__html'
            )

            if (htmlProperty && htmlProperty.type === 'ObjectProperty') {
              const htmlValue = htmlProperty.value as Expression
              if (hasDynamicContent(htmlValue)) {
                issues.push({
                  message:
                    'Unsafe dangerouslySetInnerHTML: Using dangerouslySetInnerHTML with untrusted input can lead to XSS attacks. Consider using a sanitization library like DOMPurify or avoid using this prop',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
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
