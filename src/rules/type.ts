import type { Node } from '@babel/types'
import type { ReportIssue } from '../report'

export type Rule = {
  name: string
  description: string
  check: (node: Node, filename: string) => ReportIssue[]
}
