import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-unsafe-spawn rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('no-unsafe-spawn')
  })

  it('should detect child_process.spawn with template literal', () => {
    const code = 'child_process.spawn(`ls ${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe command execution')
    expect(issues[0]!.message).toContain('spawn')
  })

  it('should detect child_process.spawnSync with binary expression', () => {
    const code = 'child_process.spawnSync("ls " + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('spawnSync')
  })

  it('should detect child_process.spawn with shell: true option', () => {
    const code = "child_process.spawn('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('shell: true')
  })

  it('should detect child_process.spawnSync with shell: true option', () => {
    const code = "child_process.spawnSync('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('shell: true')
  })

  it('should detect require child_process.spawn with template literal', () => {
    const code = "require('child_process').spawn(`ls ${userInput}`)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain("require('child_process')")
  })

  it('should detect require child_process.spawn with shell: true option', () => {
    const code = "require('child_process').spawn('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('shell: true')
  })

  it('should detect direct spawn call with template literal', () => {
    const code = 'spawn(`ls ${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('spawn')
  })

  it('should detect spawnSync with binary expression', () => {
    const code = 'spawnSync("ls " + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('spawnSync')
  })

  it('should detect direct spawn call with shell: true option', () => {
    const code = "spawn('ls', { shell: true })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('shell: true')
  })

  it('should not detect child_process.spawn with static string', () => {
    const code = "child_process.spawn('ls')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.spawnSync with static string', () => {
    const code = "child_process.spawnSync('ls')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.spawn with shell: false option', () => {
    const code = "child_process.spawn('ls', { shell: false })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect child_process.spawn with array arguments', () => {
    const code = "child_process.spawn('ls', ['-la'])"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other child_process methods', () => {
    const code = 'child_process.exec("ls")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple unsafe spawn calls', () => {
    const code = 'child_process.spawn(`ls ${x}`); spawnSync("ls " + y)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect both template literal and shell: true in same call', () => {
    const code = 'child_process.spawn(`ls ${x}`, { shell: true })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })
})
