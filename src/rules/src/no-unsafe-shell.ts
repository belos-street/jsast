import type { Rule } from '..'
import type { RuleIssue } from '../type'

export const noUnsafeShellRule: Rule = {
  name: 'no-unsafe-shell',
  description: 'Detects command execution with shell option enabled',
  severity: 'warning',
  category: 'command-injection',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee
      const shellMethods = ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync']

      if (callee.type === 'MemberExpression') {
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'child_process' &&
          callee.property.type === 'Identifier' &&
          shellMethods.includes(callee.property.name)
        ) {
          const hasShellOption = checkShellOption(node.arguments)
          if (hasShellOption) {
            issues.push({
              message: `Unsafe command execution: ${callee.property.name} uses shell option, which enables shell interpretation and may lead to command injection vulnerabilities`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }

        if (
          callee.object.type === 'CallExpression' &&
          callee.object.callee.type === 'Identifier' &&
          callee.object.callee.name === 'require' &&
          callee.object.arguments.length > 0
        ) {
          const requireArg = callee.object.arguments[0]
          if (
            requireArg &&
            requireArg.type === 'StringLiteral' &&
            requireArg.value === 'child_process' &&
            callee.property.type === 'Identifier' &&
            shellMethods.includes(callee.property.name)
          ) {
            const hasShellOption = checkShellOption(node.arguments)
            if (hasShellOption) {
              issues.push({
                message: `Unsafe command execution: require('child_process').${callee.property.name} uses shell option, which enables shell interpretation and may lead to command injection vulnerabilities`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }
          }
        }
      }

      if (callee.type === 'Identifier' && shellMethods.includes(callee.name)) {
        const hasShellOption = checkShellOption(node.arguments)
        if (hasShellOption) {
          issues.push({
            message: `Unsafe command execution: ${callee.name} uses shell option, which enables shell interpretation and may lead to command injection vulnerabilities`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    return issues
  }
}

function checkShellOption(args: any[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg && arg.type === 'ObjectExpression' && arg.properties) {
      for (const prop of arg.properties) {
        if (
          prop.type === 'ObjectProperty' &&
          prop.key.type === 'Identifier' &&
          prop.key.name === 'shell'
        ) {
          if (
            prop.value.type === 'BooleanLiteral' &&
            prop.value.value === true
          ) {
            return true
          }
          if (
            prop.value.type === 'StringLiteral' &&
            prop.value.value.length > 0
          ) {
            return true
          }
        }
      }
    }
  }
  return false
}
