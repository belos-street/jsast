import traverse from '@babel/traverse'
import type { File } from '@babel/types'
import type { Rule } from '@/rules'
import type { ReportIssue } from '@/report'

/**
 * 遍历AST并应用规则检查
 * @param ast 解析后的AST对象
 * @param rules 要应用的规则列表
 * @param filename 文件名
 * @returns 检查出的问题列表
 */
export function traverseAndCheck(ast: File, rules: Rule[], filename: string): ReportIssue[] {
  const issues: ReportIssue[] = []

  traverse(ast, {
    enter: (path) => {
      for (const rule of rules) {
        const ruleIssues = rule.check(path.node, filename)
        // 自动添加规则的severity到每个issue
        const issuesWithSeverity = ruleIssues.map((issue) => ({
          ...issue,
          severity: rule.severity
        }))
        issues.push(...issuesWithSeverity)
      }
    }
  })

  return issues
}
