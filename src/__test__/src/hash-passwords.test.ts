import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('hash-passwords rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('hash-passwords')
  })

  it('should detect plaintext password in object assignment', () => {
    const code = 'user.password = "secret"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should detect plaintext password in database insert', () => {
    const code = "db.insert({ username: 'john', password: 'secret123' })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should detect plaintext password in database update', () => {
    const code = "db.update({ password: 'newpass' })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should detect plaintext password in model create', () => {
    const code = "User.create({ password: 'plaintext' })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should detect plaintext password in model save', () => {
    const code = 'user.save({ password: "secret" })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should detect plaintext password in set method', () => {
    const code = "user.set('password', 'plaintext')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should not detect password when using bcrypt hash', () => {
    const code = "const user = { password: await bcrypt.hash('plaintext', 10) }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect password when using crypto createHash', () => {
    const code = "const user = { password: crypto.createHash('sha256').update('plaintext').digest('hex') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect password when using bcryptjs hash', () => {
    const code = 'user.password = bcryptjs.hashSync("secret", 10)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect password when using bcrypt compare', () => {
    const code = 'bcrypt.compare(plaintext, hashedPassword)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect plaintext password in object assignment', () => {
    const code = 'user.password = `${userInput}`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('password')
  })

  it('should not detect non-password fields', () => {
    const code = "const user = { username: 'john', email: 'john@example.com' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect passwd field variant', () => {
    const code = 'user.passwd = "secret"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('passwd')
  })

  it('should detect pwd field variant', () => {
    const code = 'user.pwd = "secret"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('pwd')
  })

  it('should detect user_password field variant', () => {
    const code = "db.insert({ user_password: 'secret' })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('user_password')
  })
})
