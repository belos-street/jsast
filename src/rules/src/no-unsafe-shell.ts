import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 不安全的 shell 选项检测规则
 *
 * 设计思路：
 * 1. 检测 child_process 模块的 spawn、spawnSync、exec、execSync、execFile、execFileSync 调用
 * 2. 检查参数对象中是否包含 shell 选项
 * 3. 判断 shell 选项是否为 true 或非空字符串
 * 4. 支持多种调用模式：直接调用、require 调用、变量引用
 *
 * 检测范围：
 * - child_process.spawn('cmd', { shell: true }): shell 选项为 true
 * - child_process.spawn('cmd', { shell: '/bin/bash' }): shell 选项为字符串
 * - child_process.exec('cmd', { shell: true }): exec 方法
 * - require('child_process').spawn('cmd', { shell: true }): require 调用
 * - spawn('cmd', { shell: true }): 直接调用
 *
 * 安全模式（不检测）：
 * - 禁用 shell：child_process.spawn('cmd', { shell: false })
 * - 无 shell 选项：child_process.spawn('cmd', {})
 * - shell 选项为空字符串：child_process.spawn('cmd', { shell: '' })
 */
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
