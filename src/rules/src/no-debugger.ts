import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用debugger语句规则
 *
 * 设计思路：
 * 1. 检测代码中的debugger语句
 * 2. debugger语句会暂停代码执行，影响生产环境
 * 3. 应该在发布前移除所有debugger语句
 *
 * 检测范围：
 * - debugger语句
 *
 * 安全模式（不检测）：
 * - 无（debugger语句在生产环境中应该完全移除）
 */

export const noDebuggerRule: Rule = {
  name: 'no-debugger',
  description: 'Disallow debugger statements',
  severity: 'error',
  category: 'code-quality',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'DebuggerStatement' && node.loc) {
      issues.push({
        message: `Debugger statement found: Remove debugger statements before deploying to production. Debugger statements pause execution and should not be present in production code`,
        line: node.loc.start.line,
        column: node.loc.start.column
      })
    }

    return issues
  }
}
