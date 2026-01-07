import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用console.log规则
 */
export const noConsoleLogRule: Rule = {
  name: 'no-console-log',
  description: 'Disallows the use of console.log',
  severity: 'low',
  category: 'code-quality',
  check(node) {
    const issues: RuleIssue[] = []
    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === 'console' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'log' &&
      node.loc
    ) {
      issues.push({
        message: 'Do not use console.log',
        line: node.loc.start.line,
        column: node.loc.start.column
      })
    }
    return issues
  }
}
