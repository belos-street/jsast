import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用alert规则
 *
 * 设计思路：
 * 1. 检测代码中的alert调用
 * 2. alert会阻塞浏览器，影响用户体验
 * 3. 生产环境应使用更友好的提示方式
 *
 * 检测范围：
 * - alert() 调用
 * - window.alert() 调用
 *
 * 安全模式（不检测）：
 * - alert作为变量名或属性名（非调用）
 * - 其他对象的方法调用
 */

export const noAlertRule: Rule = {
  name: 'no-alert',
  description: 'Disallow alert calls',
  severity: 'warning',
  category: 'code-quality',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'Identifier' && callee.name === 'alert') {
        issues.push({
          message: `Alert call found: Avoid using alert() in production code. Use more user-friendly notification methods like toast notifications, modal dialogs, or console.log for debugging`,
          line: node.loc.start.line,
          column: node.loc.start.column
        })
      }

      if (callee.type === 'MemberExpression') {
        const object = callee.object
        const property = callee.property

        if (property.type === 'Identifier' && property.name === 'alert') {
          if (object.type === 'Identifier' && object.name === 'window') {
            issues.push({
              message: `Alert call found: Avoid using window.alert() in production code. Use more user-friendly notification methods like toast notifications, modal dialogs, or console.log for debugging`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    return issues
  }
}
