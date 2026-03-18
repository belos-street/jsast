import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-ssl-verification-disabled rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-ssl-verification-disabled')
  })

  it('should detect rejectUnauthorized set to false', () => {
    const code = 'https.globalAgent.options.rejectUnauthorized = false'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rejectUnauthorized')
    expect(issues[0]!.message).toContain('SSL')
  })

  it('should detect NODE_TLS_REJECT_UNAUTHORIZED set to 0', () => {
    const code = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('NODE_TLS_REJECT_UNAUTHORIZED')
  })

  it('should detect NODE_TLS_REJECT_UNAUTHORIZED set to false string', () => {
    const code = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 'false'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('NODE_TLS_REJECT_UNAUTHORIZED')
  })

  it('should detect rejectUnauthorized in object property', () => {
    const code = 'const options = { rejectUnauthorized: false }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rejectUnauthorized')
  })

  it('should detect secure set to false in object', () => {
    const code = 'const options = { secure: false }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('secure')
  })

  it('should detect agent.options.rejectUnauthorized assignment', () => {
    const code = 'agent.options.rejectUnauthorized = false'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rejectUnauthorized')
  })

  it('should not detect rejectUnauthorized set to true', () => {
    const code = 'https.globalAgent.options.rejectUnauthorized = true'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect secure set to true', () => {
    const code = 'const options = { secure: true }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect normal environment variable values', () => {
    const code = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect rejectUnauthorized with string 0', () => {
    const code = "https.globalAgent.options.rejectUnauthorized = '0'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rejectUnauthorized')
  })
})
