import type { Rule } from '..'
import type { RuleIssue } from '../type'

export const unsafeSpawnRule: Rule = {
  name: 'no-unsafe-spawn',
  description: 'Detects unsafe spawn function calls',
  severity: 'error',
  category: 'command-injection',
  check(node) {
    const issues: RuleIssue[] = []

    // Detect unsafe spawn function calls
    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      // Check for direct calls to child_process.spawn/spawnSync
      if (callee.type === 'MemberExpression') {
        // Detect pattern: child_process.spawn('...')
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'child_process' &&
          callee.property.type === 'Identifier' &&
          ['spawn', 'spawnSync'].includes(callee.property.name)
        ) {
          const firstArg = node.arguments[0]
          // Check if first argument is template string or binary expression (concatenation)
          if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
            issues.push({
              message: `Unsafe command execution: ${callee.property.name} uses dynamically concatenated command string, vulnerable to command injection`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }

          // Check for shell: true option
          if (node.arguments.length > 1) {
            const secondArg = node.arguments[1]
            if (secondArg && secondArg.type === 'ObjectExpression') {
              for (const prop of secondArg.properties) {
                if (
                  prop.type === 'ObjectProperty' &&
                  prop.key.type === 'Identifier' &&
                  prop.key.name === 'shell' &&
                  prop.value.type === 'BooleanLiteral' &&
                  prop.value.value === true
                ) {
                  issues.push({
                    message: `Unsafe command execution: ${callee.property.name} uses shell: true option, vulnerable to command injection`,
                    line: node.loc.start.line,
                    column: node.loc.start.column
                  })
                }
              }
            }
          }
        }

        // Detect pattern: require('child_process').spawn('...')
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
            ['spawn', 'spawnSync'].includes(callee.property.name)
          ) {
            const firstArg = node.arguments[0]
            if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
              issues.push({
                message: `Unsafe command execution: require('child_process').${callee.property.name} uses dynamically concatenated command string, vulnerable to command injection`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }

            // Check for shell: true option
            if (node.arguments.length > 1) {
              const secondArg = node.arguments[1]
              if (secondArg && secondArg.type === 'ObjectExpression') {
                for (const prop of secondArg.properties) {
                  if (
                    prop.type === 'ObjectProperty' &&
                    prop.key.type === 'Identifier' &&
                    prop.key.name === 'shell' &&
                    prop.value.type === 'BooleanLiteral' &&
                    prop.value.value === true
                  ) {
                    issues.push({
                      message: `Unsafe command execution: require('child_process').${callee.property.name} uses shell: true option, vulnerable to command injection`,
                      line: node.loc.start.line,
                      column: node.loc.start.column
                    })
                  }
                }
              }
            }
          }
        }
      }

      // Detect pattern: direct call to spawn('...') (assuming already imported)
      if (callee.type === 'Identifier' && ['spawn', 'spawnSync'].includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
          issues.push({
            message: `Unsafe command execution: ${callee.name} uses dynamically concatenated command string, vulnerable to command injection`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }

        // Check for shell: true option
        if (node.arguments.length > 1) {
          const secondArg = node.arguments[1]
          if (secondArg && secondArg.type === 'ObjectExpression') {
            for (const prop of secondArg.properties) {
              if (
                prop.type === 'ObjectProperty' &&
                prop.key.type === 'Identifier' &&
                prop.key.name === 'shell' &&
                prop.value.type === 'BooleanLiteral' &&
                prop.value.value === true
              ) {
                issues.push({
                  message: `Unsafe command execution: ${callee.name} uses shell: true option, vulnerable to command injection`,
                  line: node.loc.start.line,
                  column: node.loc.start.column
                })
              }
            }
          }
        }
      }
    }

    return issues
  }
}
