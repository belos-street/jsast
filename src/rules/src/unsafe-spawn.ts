import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 不安全的 spawn 函数调用检测规则
 *
 * 设计思路：
 * 1. 检测 child_process.spawn 和 spawnSync 的调用
 * 2. 检查第一个参数是否为动态拼接的命令字符串（模板字符串或二元表达式）
 * 3. 检查第二个参数（选项对象）是否包含 shell: true 配置
 * 4. 支持多种调用模式：直接调用、require 调用、变量引用
 *
 * 检测范围：
 * - child_process.spawn(`cmd ${userInput}`): 动态命令字符串
 * - child_process.spawn('cmd' + userInput): 字符串拼接
 * - child_process.spawn('cmd', { shell: true }): 启用 shell 选项
 * - require('child_process').spawn(`cmd ${userInput}`): require 调用
 * - spawn('cmd', { shell: true }): 直接调用
 *
 * 安全模式（不检测）：
 * - 静态命令：child_process.spawn('ls', ['-la'])
 * - 禁用 shell：child_process.spawn('cmd', { shell: false })
 */
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
