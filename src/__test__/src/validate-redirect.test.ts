import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('validate-redirect rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('validate-redirect')
  })

  it('should detect Express res.redirect with user input', () => {
    const code = "res.redirect(userInput)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should detect Koa ctx.redirect with user input', () => {
    const code = "ctx.redirect(url)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should detect window.location.href assignment with user input', () => {
    const code = "window.location.href = userInput"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('location')
  })

  it('should detect location.href assignment with user input', () => {
    const code = "location.href = userInput"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('location')
  })

  it('should detect window.location.replace with user input', () => {
    const code = "window.location.replace(userInput)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should detect location.replace with user input', () => {
    const code = "location.replace(userInput)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should detect external URL redirect', () => {
    const code = "res.redirect('https://evil.com' + path)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should detect path traversal redirect', () => {
    const code = "res.redirect('/' + userInput + '/profile')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should not detect static whitelist path redirect', () => {
    const code = "res.redirect('/home')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect localhost redirect', () => {
    const code = "res.redirect('http://localhost:3000/home')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect environment variable redirect', () => {
    const code = "res.redirect(process.env.REDIRECT_URL)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect window.location.href = external URL', () => {
    const code = "window.location.href = 'https://evil.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })

  it('should detect path traversal in window.location.assign', () => {
    const code = "window.location.assign('../external')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('redirect')
  })
})