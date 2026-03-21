import type { Node } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止空的catch块规则
 *
 * 设计思路：
 * 1. 检测空的catch块
 * 2. 空的catch块会吞掉错误，导致问题难以排查
 * 3. 应该至少记录错误或进行适当的错误处理
 *
 * 检测范围：
 * - 空的catch块
 * - catch块中只有注释
 *
 * 安全模式（不检测）：
 * - catch块中有错误处理逻辑
 * - catch块中有日志记录
 * - catch块中有错误上报
 */

function isEmptyBlock(node: Node): boolean {
  if (node.type === 'BlockStatement') {
    const body = node.body
    if (body.length === 0) {
      return true
    }
    const hasOnlyComments = body.every((stmt: Node) => stmt.type === 'EmptyStatement')
    return hasOnlyComments
  }
  return false
}

export const handleErrorsRule: Rule = {
  name: 'handle-errors',
  description: 'Disallow empty catch blocks',
  severity: 'warning',
  category: 'code-quality',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CatchClause' && node.loc) {
      const body = node.body
      if (isEmptyBlock(body)) {
        issues.push({
          message: `Empty catch block found: Empty catch blocks swallow errors and make debugging difficult. Add proper error handling such as logging, error reporting, or re-throwing the error`,
          line: node.loc.start.line,
          column: node.loc.start.column
        })
      }
    }

    return issues
  }
}