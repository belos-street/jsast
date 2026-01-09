import type { Rule } from '..'
import type { RuleIssue } from '../type'

export const noEvalRule: Rule = {
  name: 'no-eval',
  description: 'Detects use of eval, setTimeout, and setInterval with string arguments',
  severity: 'error',
  category: 'xss',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'Identifier') {
        const functionName = callee.name

        if (functionName === 'eval') {
          issues.push({
            message: 'Avoid using eval: eval executes arbitrary code and can lead to code injection vulnerabilities',
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        } else if (functionName === 'setTimeout' || functionName === 'setInterval') {
          const firstArg = node.arguments[0]
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            issues.push({
              message: `Avoid using ${functionName} with string argument: ${functionName} with string argument executes arbitrary code and can lead to code injection vulnerabilities`,
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
