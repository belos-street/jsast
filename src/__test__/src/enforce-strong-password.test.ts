import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('enforce-strong-password rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('enforce-strong-password')
  })

  it('should detect weak password length check (< 8)', () => {
    const code = 'function validate(password) { if (password.length < 6) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Weak password policy')
    expect(issues[0]!.message).toContain('8')
  })

  it('should detect weak password length check with 5', () => {
    const code = 'function validate(userPassword) { if (userPassword.length < 5) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Weak password policy')
  })

  it('should detect weak password length check with 4', () => {
    const code = 'function validate(pwd) { if (pwd.length < 4) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Weak password policy')
  })

  it('should not detect strong password length check (>= 8)', () => {
    const code = 'function validate(password) { if (password.length < 8) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect strong password length check with 10', () => {
    const code = 'function validate(password) { if (password.length < 10) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect unrelated validation functions', () => {
    const code = 'function validate(email) { if (email.length < 5) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect length checks for non-password fields', () => {
    const code = 'function validate(username) { if (username.length < 3) { return false } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })
})
