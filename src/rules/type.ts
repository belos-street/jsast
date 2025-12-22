import type { Node } from '@babel/types'
import type { ReportIssue } from '../report'

export type Rule = {
  name: string
  description: string
  severity: 'high' | 'medium' | 'low'
  check: (node: Node, filename: string) => ReportIssue[]
}
