import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('regenerate-session rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('regenerate-session')
  })

  it('should detect missing session regenerate after login', () => {
    const code = 'function handler() { if (login(username, password)) { return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Session fixation risk')
  })

  it('should detect missing session regenerate after authenticate', () => {
    const code = 'function handler() { if (authenticate(user)) { return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Session fixation risk')
  })

  it('should detect missing session regenerate after signIn', () => {
    const code = 'function handler() { if (signIn(email, password)) { return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Session fixation risk')
  })

  it('should not detect when session.regenerate is called', () => {
    const code = 'function handler() { if (login(username, password)) { session.regenerate(); return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect when session.regenerateId is called', () => {
    const code = 'function handler() { if (authenticate(user)) { session.regenerateId(); return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect when req.session.regenerate is called', () => {
    const code = 'function handler() { if (login(username, password)) { req.session.regenerate(); return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect missing session regenerate in nested if', () => {
    const code = 'function handler() { if (login(username, password)) { if (user) { return "success" } } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Session fixation risk')
  })

  it('should not detect when session.regenerate is in nested if', () => {
    const code = 'function handler() { if (login(username, password)) { if (user) { session.regenerate(); return "success" } } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect missing session regenerate with authenticated check', () => {
    const code = 'function handler() { if (authenticated) { return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Session fixation risk')
  })

  it('should detect missing session regenerate with success check', () => {
    const code = 'function handler() { if (success) { return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Session fixation risk')
  })

  it('should not detect unrelated if statements', () => {
    const code = 'function handler() { if (user.isAdmin) { return "admin" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect when session.save is called', () => {
    const code = 'function handler() { if (login(username, password)) { session.save(); return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect when session.reload is called', () => {
    const code = 'function handler() { if (authenticate(user)) { session.reload(); return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect when session.touch is called', () => {
    const code = 'function handler() { if (signIn(email, password)) { session.touch(); return "success" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })
})