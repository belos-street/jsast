import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-dynamic-assignment rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-dynamic-assignment')
  })

  it('should detect window[variable] assignment', () => {
    const code = 'window[userInput] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic window property assignment')
  })

  it('should detect global[variable] assignment', () => {
    const code = 'global[userInput] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic global property assignment')
  })

  it('should detect globalThis[variable] assignment', () => {
    const code = 'globalThis[userInput] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic globalThis property assignment')
  })

  it('should detect self[variable] assignment', () => {
    const code = 'self[userInput] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic self property assignment')
  })

  it('should detect this[variable] assignment', () => {
    const code = 'this[userInput] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic this property assignment')
  })

  it('should not detect window with static property', () => {
    const code = 'window.location = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect window[variable] with string literal', () => {
    const code = "window['userInput'] = value"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect normal variable assignment', () => {
    const code = 'const x = 1'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect normal object property assignment', () => {
    const code = 'obj.key = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect static array access assignment', () => {
    const code = 'arr[0] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple dynamic assignments', () => {
    const code = 'window[a] = 1; global[b] = 2'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect window without bracket notation', () => {
    const code = 'window = something'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect global without bracket notation', () => {
    const code = 'global = something'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect this without bracket notation', () => {
    const code = 'this.x = 1'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect string literal as computed property', () => {
    const code = "window['location'] = value"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect dynamic assignment in function', () => {
    const code = 'function test() { window[key] = value }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic window property assignment')
  })

  it('should detect dynamic assignment in arrow function', () => {
    const code = 'const test = () => { global[key] = value }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Dynamic global property assignment')
  })
})
