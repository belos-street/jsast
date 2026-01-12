import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 命令行注入检测规则
 *
 * 设计思路：
 * 1. 检测 child_process 模块的 exec、execSync、execFile、execFileSync 方法调用
 * 2. 检查第一个参数是否为动态拼接的命令字符串（模板字符串或二元表达式）
 * 3. 支持多种调用模式：直接调用、require 调用、变量引用
 *
 * 检测范围：
 * - child_process.exec(`cmd ${userInput}`): 动态命令字符串
 * - child_process.execSync('cmd' + userInput): 字符串拼接
 * - child_process.execFile(`cmd ${userInput}`): execFile 方法
 * - require('child_process').exec(`cmd ${userInput}`): require 调用
 * - exec(`cmd ${userInput}`): 直接调用
 *
 * 安全模式（不检测）：
 * - 静态命令：child_process.exec('ls -la')
 * - 字符串字面量：child_process.execSync('echo hello')
 */
export const commandInjectionRule: Rule = {
  name: 'command-injection',
  description: 'Detects command injection vulnerabilities',
  severity: 'error',
  category: 'command-injection',
  check(node) {
    const issues: RuleIssue[] = []

    // Detect unsafe child_process function calls
    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      // Check for direct calls to child_process.exec/execSync/spawnSync etc.
      if (callee.type === 'MemberExpression') {
        // Detect pattern: child_process.exec('...')
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'child_process' &&
          callee.property.type === 'Identifier' &&
          ['exec', 'execSync', 'execFile', 'execFileSync'].includes(callee.property.name)
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
        }

        // Detect pattern: require('child_process').exec('...')
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
            ['exec', 'execSync', 'execFile', 'execFileSync'].includes(callee.property.name)
          ) {
            const firstArg = node.arguments[0]
            if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
              issues.push({
                message: `Unsafe command execution: require('child_process').${callee.property.name} uses dynamically concatenated command string, vulnerable to command injection`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }
          }
        }
      }

      // Detect pattern: direct call to exec('...') (assuming already imported)
      if (callee.type === 'Identifier' && ['exec', 'execSync'].includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
          issues.push({
            message: `Unsafe command execution: ${callee.name} uses dynamically concatenated command string, vulnerable to command injection`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    return issues
  }
}
