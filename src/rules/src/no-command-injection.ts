import type { Rule } from '..'
import type { ReportIssue } from '@/report'
import type { Node } from '@babel/types'

/**
 * 命令行注入检测规则
 */
export const noCommandInjectionRule: Rule = {
  name: 'no-command-injection',
  description: '检测命令行注入风险',
  severity: 'high',
  check(node: Node, filename: string): Omit<ReportIssue, 'severity'>[] {
    const issues: Omit<ReportIssue, 'severity'>[] = []

    // 检测不安全的child_process函数调用
    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      // 检查直接调用child_process.exec/execSync/spawnSync等
      if (callee.type === 'MemberExpression') {
        // 检测形式：child_process.exec('...')
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'child_process' &&
          callee.property.type === 'Identifier' &&
          ['exec', 'execSync', 'execFile', 'execFileSync'].includes(callee.property.name)
        ) {
          const firstArg = node.arguments[0]
          // 检查第一个参数是否是模板字符串或二元表达式（拼接）
          if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
            issues.push({
              rule: 'no-command-injection',
              message: `不安全的命令执行：${callee.property.name} 使用了动态拼接的命令字符串，存在命令注入风险`,
              line: node.loc.start.line,
              column: node.loc.start.column,
              filename
            })
          }
        }

        // 检测形式：require('child_process').exec('...')
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
                rule: 'no-command-injection',
                message: `不安全的命令执行：require('child_process').${callee.property.name} 使用了动态拼接的命令字符串，存在命令注入风险`,
                line: node.loc.start.line,
                column: node.loc.start.column,
                filename
              })
            }
          }
        }
      }

      // 检测形式：直接调用exec('...')（假设已导入）
      if (callee.type === 'Identifier' && ['exec', 'execSync'].includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
          issues.push({
            rule: 'no-command-injection',
            message: `不安全的命令执行：${callee.name} 使用了动态拼接的命令字符串，存在命令注入风险`,
            line: node.loc.start.line,
            column: node.loc.start.column,
            filename
          })
        }
      }
    }

    return issues
  }
}
