import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用var关键字规则
 */
export const varRule: Rule = {
  name: 'no-var',
  description: 'Disallows the use of var keyword',
  severity: 'medium',
  category: 'code-quality',
  check(node) {
    const issues: RuleIssue[] = []
    if (node.type === 'VariableDeclaration' && node.kind === 'var' && node.loc) {
      issues.push({
        message: 'Do not use var keyword, use let or const instead',
        line: node.loc.start.line,
        column: node.loc.start.column
      })
    }
    return issues
  }
}
