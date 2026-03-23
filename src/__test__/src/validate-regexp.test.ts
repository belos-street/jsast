import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('validate-regexp rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('validate-regexp')
  })

  it('should detect nested quantifier (a+)+', () => {
    const code = 'const regex = /(a+)+/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe regular expression')
    expect(issues[0]!.message).toContain('Nested quantifier')
  })

  it('should detect nested quantifier (a*)+', () => {
    const code = 'const regex = /(a*)+/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Nested quantifier')
  })

  it('should detect nested quantifier (a+)*', () => {
    const code = 'const regex = /(a+)*/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Nested quantifier')
  })

  it('should detect overlapping wildcards .*.*', () => {
    const code = 'const regex = /.*.*/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Overlapping wildcards')
  })

  it('should detect overlapping wildcards .+.*', () => {
    const code = 'const regex = /.+.*/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Overlapping wildcards')
  })

  it('should not detect safe regex', () => {
    const code = 'const regex = /^test[abc]+$/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect simple regex', () => {
    const code = 'const regex = /hello/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect unsafe regex with new RegExp', () => {
    const code = 'const regex = new RegExp("(a+)+")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe regular expression')
  })

  it('should detect unsafe regex with RegExp call', () => {
    const code = 'const regex = RegExp("(a+)+")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe regular expression')
  })

  it('should detect dynamic regex with new RegExp', () => {
    const code = 'const regex = new RegExp(userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic regular expression')
  })

  it('should detect dynamic regex with RegExp call', () => {
    const code = 'const regex = RegExp(userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic regular expression')
  })

  it('should not detect safe regex with new RegExp', () => {
    const code = 'const regex = new RegExp("^test$")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect unsafe regex with flags', () => {
    const code = 'const regex = /(a+)+/gi'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe regular expression')
  })

  it('should detect unsafe regex with new RegExp and flags', () => {
    const code = 'const regex = new RegExp("(a+)+", "gi")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe regular expression')
  })

  it('should detect alternation with quantifier', () => {
    const code = 'const regex = /(a|b)+/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alternation with quantifier')
  })

  it('should detect optional group with quantifier', () => {
    const code = 'const regex = /(a?)+/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Optional group with quantifier')
  })

  it('should not detect safe alternation', () => {
    const code = 'const regex = /(a|b)/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe quantifier', () => {
    const code = 'const regex = /a+/'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple unsafe patterns', () => {
    const code = `const regex1 = /(a+)+/
const regex2 = /(b+)+/`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })
})