import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-var rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.registerRule('no-var')
  })

  it('should detect var declaration', () => {
    const code = 'var x = 10'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0].message).toBe('禁止使用var关键字，请使用let或const')
    expect(issues[0].line).toBe(1)
    expect(issues[0].column).toBe(0)
  })

  it('should detect multiple var declarations', () => {
    const code = 'var x = 10; var y = 20'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect let declaration', () => {
    const code = 'let x = 10'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect const declaration', () => {
    const code = 'const x = 10'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should handle mixed declarations', () => {
    const code = 'var x = 10; let y = 20; const z = 30'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0].message).toBe('禁止使用var关键字，请使用let或const')
  })
})
