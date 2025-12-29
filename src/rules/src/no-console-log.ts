import type { Rule } from '..'
import type { ReportIssue } from '@/report'
import type { Node } from '@babel/types'

/**
 * 禁止使用console.log规则
 */
export const noConsoleLogRule: Rule = {
  name: 'no-console-log',
  description: '禁止使用console.log',
  severity: 'low',
  check(node: Node, filename: string): Omit<ReportIssue, 'severity'>[] {
    const issues: Omit<ReportIssue, 'severity'>[] = []
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
