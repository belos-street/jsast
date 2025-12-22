import type { Node } from '@babel/types'
import type { Rule } from '..'
import type { ReportIssue } from '@/report'

/**
 * 禁止使用var关键字规则
 */
export const noVarRule: Rule = {
  name: 'no-var',
  description: '禁止使用var关键字',
  severity: 'medium',
  check(node: Node, filename: string): ReportIssue[] {
    const issues: ReportIssue[] = []
    if (node.type === 'VariableDeclaration' && node.kind === 'var' && node.loc) {
      issues.push({
        rule: 'no-var',
        message: '禁止使用var关键字，请使用let或const',
        line: node.loc.start.line,
        column: node.loc.start.column,
        filename
      })
    }
    return issues
  }
}
