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
  | 'insecure-dependencies'
  | 'code-quality'
  | 'other-security'
  | 'insecure-auth'
  | 'hardcoded-secrets'
  | 'insecure-authentication'

export type RuleName =
  | 'no-console-log'
  | 'no-var'
  | 'command-injection'
  | 'no-unsafe-spawn'
  | 'no-unsafe-shell'
  | 'detect-sql-injection'
  | 'avoid-raw-sql'
  | 'detect-mongodb-injection'
  | 'avoid-dangerously-set-innerhtml'
  | 'avoid-unsafe-html'
  | 'no-eval'
  | 'no-document-write'
  | 'detect-path-traversal'
  | 'avoid-unsafe-fs-access'
  | 'validate-json-parse'
  | 'detect-prototype-pollution'
  | 'use-secure-random'
  | 'avoid-weak-crypto'
  | 'detect-hardcoded-secrets'
  | 'detect-hardcoded-urls'
  | 'use-https'
  | 'avoid-ssl-verification-disabled'
  | 'validate-redirect'
  | 'hash-passwords'
  | 'enforce-strong-password'
  | 'regenerate-session'
  | 'no-debugger'
  | 'no-alert'
  | 'handle-errors'
  | 'check-unused-vars'
  | 'avoid-duplicate-imports'
  | 'validate-regexp'
  | 'avoid-dynamic-assignment'
  | 'prevent-prototype-pollution'

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
