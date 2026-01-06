import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-command-injection rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.registerRule('command-injection')
  })

  it('should detect child_process.exec with template literal', () => {
    const code = 'child_process.exec(`ls ${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('不安全的命令执行')
    expect(issues[0]!.message).toContain('exec')
  })

  it('should detect child_process.execSync with binary expression', () => {
    const code = 'child_process.execSync("ls " + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('execSync')
  })

  it('should detect require child_process.exec with template literal', () => {
    const code = "require('child_process').exec(`ls ${userInput}`)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain("require('child_process')")
  })

  it('should detect direct exec call with template literal', () => {
    const code = 'exec(`ls ${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('exec')
  })

  it('should detect execSync with binary expression', () => {
    const code = 'execSync("ls " + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('execSync')
  })

  it('should not detect child_process.exec with static string', () => {
    const code = 'child_process.exec("ls")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.execSync with static string', () => {
    const code = 'child_process.execSync("ls")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other child_process methods', () => {
    const code = 'child_process.spawn("ls")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple unsafe command executions', () => {
    const code = 'child_process.exec(`ls ${x}`); execSync("ls " + y)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })
})
