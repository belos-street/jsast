export type ReportIssue = {
  rule: string
  message: string
  line: number
  column: number
  filename: string
  severity: 'high' | 'medium' | 'low'
}
