import type { Rule } from '..'
import type { RuleIssue } from '../type'

export const validateJsonParseRule: Rule = {
  name: 'validate-json-parse',
  description: 'Validate JSON.parse calls to ensure input is validated',
  severity: 'warning',
  category: 'insecure-deserialization',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'JSON' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'parse'
      ) {
        const firstArg = node.arguments[0]

        if (firstArg && firstArg.type !== 'StringLiteral') {
          issues.push({
            message:
              'Unsafe JSON.parse: JSON.parse uses unvalidated input, vulnerable to injection attacks. Use try-catch and validate input before parsing',
            line: node.loc!.start.line,
            column: node.loc!.start.column
          })
        }
      }
    }

    return issues
  }
}
