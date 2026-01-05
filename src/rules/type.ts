import type { ReportIssue } from '@/report'
import type { Node } from '@babel/types'

// 规则名称类型
export type RuleName = 'no-console-log' | 'no-var' | 'command-injection'
export type RuleIssue = Omit<ReportIssue, 'severity' | 'rule' | 'filename'>

export type Rule = {
  name: RuleName
  description: string
  severity: 'high' | 'medium' | 'low'
  check: (node: Node) => RuleIssue[]
}
