import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-eval rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('no-eval')
  })

  it('should detect eval with string literal', () => {
    const code = "eval('2 + 2')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('eval')
  })

  it('should detect eval with template literal', () => {
    const code = 'eval(`2 + ${x}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('eval')
  })

  it('should detect eval with variable', () => {
    const code = 'eval(userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('eval')
  })

  it('should detect setTimeout with string argument', () => {
    const code = "setTimeout('alert(1)', 1000)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('setTimeout')
  })

  it('should detect setTimeout with template literal', () => {
    const code = 'setTimeout(`alert(${x})`, 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('setTimeout')
  })

  it('should detect setInterval with string argument', () => {
    const code = "setInterval('alert(1)', 1000)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('setInterval')
  })

  it('should detect setInterval with template literal', () => {
    const code = 'setInterval(`alert(${x})`, 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('setInterval')
  })

  it('should not detect setTimeout with function argument', () => {
    const code = 'setTimeout(() => { alert(1) }, 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect setInterval with function argument', () => {
    const code = 'setInterval(() => { alert(1) }, 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect setTimeout with function name', () => {
    const code = 'setTimeout(myFunction, 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect setInterval with function name', () => {
    const code = 'setInterval(myFunction, 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect setTimeout with arrow function', () => {
    const code = 'setTimeout(() => console.log("test"), 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect setInterval with arrow function', () => {
    const code = 'setInterval(() => console.log("test"), 1000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple eval calls', () => {
    const code = "eval('2 + 2'); eval(`3 + ${x}`)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect setTimeout and setInterval with string arguments', () => {
    const code = "setTimeout('alert(1)', 1000); setInterval('alert(2)', 2000)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect eval, setTimeout, and setInterval together', () => {
    const code = "eval('x'); setTimeout('y', 1000); setInterval('z', 2000)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(3)
  })

  it('should detect setTimeout with string and eval together', () => {
    const code = "eval('x'); setTimeout('y', 1000)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect setTimeout with string and setInterval with string', () => {
    const code = "setTimeout('x', 1000); setInterval('y', 2000)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect setTimeout with function and setInterval with function', () => {
    const code = 'setTimeout(() => {}, 1000); setInterval(() => {}, 2000)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })
})
