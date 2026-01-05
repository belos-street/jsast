import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用var关键字规则
 */
export const varRule: Rule = {
  name: 'no-var',
  description: '禁止使用var关键字',
  severity: 'medium',
  check(node) {
    const issues: RuleIssue[] = []
    if (node.type === 'VariableDeclaration' && node.kind === 'var' && node.loc) {
      issues.push({
        message: '禁止使用var关键字，请使用let或const',
        line: node.loc.start.line,
        column: node.loc.start.column
      })
    }
    return issues
  }
}
