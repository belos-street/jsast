import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-unsafe-shell rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('no-unsafe-shell')
  })

  it('should detect child_process.spawn with shell: true', () => {
    const code = "child_process.spawn('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option') && i.message.includes('spawn'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect child_process.spawnSync with shell: true', () => {
    const code = "child_process.spawnSync('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option') && i.message.includes('spawnSync'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect child_process.exec with shell: true', () => {
    const code = "child_process.exec('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option') && i.message.includes('exec'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect child_process.execSync with shell: true', () => {
    const code = "child_process.execSync('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option') && i.message.includes('execSync'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect child_process.execFile with shell: true', () => {
    const code = "child_process.execFile('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option') && i.message.includes('execFile'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect child_process.execFileSync with shell: true', () => {
    const code = "child_process.execFileSync('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option') && i.message.includes('execFileSync'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect require child_process.spawn with shell: true', () => {
    const code = "require('child_process').spawn('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes("require('child_process')") && i.message.includes('shell option'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect require child_process.exec with shell: true', () => {
    const code = "require('child_process').exec('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes("require('child_process')") && i.message.includes('shell option'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect direct spawn call with shell: true', () => {
    const code = "spawn('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option'))
    expect(hasShellIssue).toBe(true)
  })

  it('should detect direct exec call with shell: true', () => {
    const code = "exec('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option'))
    expect(hasShellIssue).toBe(true)
  })

  it('should not detect child_process.spawn without shell option', () => {
    const code = "child_process.spawn('ls')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.spawn with shell: false', () => {
    const code = "child_process.spawn('ls', { shell: false })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.spawn with other options', () => {
    const code = "child_process.spawn('ls', ['-la'])"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.spawn with cwd option', () => {
    const code = "child_process.spawn('ls', { cwd: '/tmp' })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple shell options in different calls', () => {
    const code = "child_process.spawn('ls', { shell: true }); execSync('cat', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    const shellIssues = issues.filter((i) => i.message.includes('shell option'))
    expect(shellIssues.length).toBeGreaterThanOrEqual(2)
  })

  it('should detect shell option in second argument position', () => {
    const code = "child_process.spawn('ls', [], { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(1)
    const hasShellIssue = issues.some((i) => i.message.includes('shell option'))
    expect(hasShellIssue).toBe(true)
  })
})
