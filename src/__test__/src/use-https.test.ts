import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('use-https rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('use-https')
  })

  it('should detect HTTP URL in fetch call', () => {
    const code = "fetch('http://api.example.com')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('HTTP')
    expect(issues[0]!.message).toContain('HTTPS')
  })

  it('should detect HTTP URL in axios.get call', () => {
    const code = "axios.get('http://api.example.com')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('HTTP')
  })

  it('should detect HTTP URL in axios.post call', () => {
    const code = "axios.post('http://api.example.com', data)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('HTTP')
  })

  it('should not detect HTTP URL in standalone string literal', () => {
    const code = "const url = 'http://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect HTTP URL in template literal', () => {
    const code = 'const url = `http://${host}/api`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect HTTPS URL', () => {
    const code = "fetch('https://api.example.com')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect localhost URL', () => {
    const code = "fetch('http://localhost:3000/api')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect 127.0.0.1 URL', () => {
    const code = "fetch('http://127.0.0.1:8080/api')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect HTTPS URL in string literal', () => {
    const code = "const url = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect HTTP URL in http.request', () => {
    const code = "http.request('http://api.example.com')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('HTTP')
  })

  it('should detect HTTP URL in https.request', () => {
    const code = "https.request('http://api.example.com')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('HTTP')
  })

  it('should detect HTTP URL with long path', () => {
    const code = "fetch('http://api.example.com/v1/users/profile/settings')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('HTTP')
  })
})
