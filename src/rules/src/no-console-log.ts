import type { Rule, ReportIssue } from '../../core'
import type { Node } from '@babel/types'

/**
 * 禁止使用console.log规则
 */
export const noConsoleLogRule: Rule = {
  name: 'no-console-log',
  description: '禁止使用console.log',
  check(node: Node, filename: string): ReportIssue[] {
    const issues: ReportIssue[] = []
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
        rule: 'no-console-log',
        message: '禁止使用console.log',
        line: node.loc.start.line,
        column: node.loc.start.column,
        filename
      })
    }
    return issues
  }
}
