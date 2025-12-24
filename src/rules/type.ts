import type { Node } from '@babel/types'
import type { ReportIssue } from '../report'

// 规则名称类型
export type RuleName = 'no-console-log' | 'no-var' | 'no-command-injection'

export type Rule = {
  name: RuleName
  description: string
  severity: 'high' | 'medium' | 'low'
  check: (node: Node, filename: string) => ReportIssue[]
}
