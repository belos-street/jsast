import type { ReportIssue } from '@/report'
import type { Node } from '@babel/types'

export type RuleCategory =
  | 'command-injection'
  | 'sql-injection'
  | 'xss'
  | 'path-traversal'
  | 'insecure-deserialization'
  | 'insecure-randomness'
  | 'hardcoded-secrets'
  | 'insecure-http'
  | 'insecure-auth'
  | 'insecure-dependencies'
  | 'code-quality'
  | 'other-security'

export type RuleName =
  | 'no-console-log'
  | 'no-var'
  | 'command-injection'
  | 'no-unsafe-spawn'
  | 'no-unsafe-shell'
  | 'detect-sql-injection'
  | 'avoid-raw-sql'
  | 'detect-mongodb-injection'
export type RuleIssue = Omit<ReportIssue, 'severity' | 'rule' | 'filename'>

export type Rule = {
  name: RuleName
  description: string
  fullDescription?: string
  helpUri?: string
  severity: 'error' | 'warning' | 'note'
  category: RuleCategory
  check: (node: Node) => RuleIssue[]
}
