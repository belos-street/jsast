import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-debugger rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('no-debugger')
  })

  it('should detect debugger statement', () => {
    const code = 'debugger'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger statement in function', () => {
    const code = 'function test() { debugger }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger statement in if block', () => {
    const code = 'if (condition) { debugger }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger statement in for loop', () => {
    const code = 'for (let i = 0; i < 10; i++) { debugger }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger statement in while loop', () => {
    const code = 'while (condition) { debugger }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect multiple debugger statements', () => {
    const code = 'function test() { debugger; debugger; }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect code without debugger', () => {
    const code = 'function test() { console.log("hello"); }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect debugger as string', () => {
    const code = 'const str = "debugger"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect debugger as property name', () => {
    const code = 'obj.debugger = true'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect debugger in try-catch block', () => {
    const code = 'try { debugger } catch (e) { console.error(e) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger in switch case', () => {
    const code = 'switch (x) { case 1: debugger; break; }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger in arrow function', () => {
    const code = 'const test = () => { debugger }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })

  it('should detect debugger in class method', () => {
    const code = 'class Test { method() { debugger } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Debugger statement found')
  })
})