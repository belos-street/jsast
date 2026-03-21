import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-alert rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('no-alert')
  })

  it('should detect alert call', () => {
    const code = 'alert("hello")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect window.alert call', () => {
    const code = 'window.alert("hello")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect alert call in function', () => {
    const code = 'function test() { alert("hello") }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect alert call in if block', () => {
    const code = 'if (condition) { alert("error") }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect multiple alert calls', () => {
    const code = 'alert("first"); alert("second")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect alert as variable name', () => {
    const code = 'const alert = "test"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect alert as property name', () => {
    const code = 'obj.alert = true'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect alert in string', () => {
    const code = 'const str = "alert"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other window methods', () => {
    const code = 'window.console.log("hello")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect alert method on other objects', () => {
    const code = 'myObject.alert("test")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect alert call in try-catch block', () => {
    const code = 'try { alert("error") } catch (e) { console.error(e) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect alert call in arrow function', () => {
    const code = 'const test = () => { alert("hello") }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect alert call in class method', () => {
    const code = 'class Test { method() { alert("hello") } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })

  it('should detect alert call with variable argument', () => {
    const code = 'alert(message)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Alert call found')
  })
})