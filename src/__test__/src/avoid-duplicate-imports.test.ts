import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-duplicate-imports rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-duplicate-imports')
  })

  it('should detect duplicate imports from same module', () => {
    const code = `import { a } from 'module'
import { b } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Duplicate imports found')
    expect(issues[0]!.message).toContain('module')
  })

  it('should not detect single import', () => {
    const code = `import { a, b } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect imports from different modules', () => {
    const code = `import { a } from 'module1'
import { b } from 'module2'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect duplicate default imports', () => {
    const code = `import a from 'module'
import b from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Duplicate imports found')
  })

  it('should detect mixed imports from same module', () => {
    const code = `import a from 'module'
import { b } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Duplicate imports found')
  })

  it('should detect multiple duplicate imports', () => {
    const code = `import { a } from 'module'
import { b } from 'module'
import { c } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('lines: 1, 2, 3')
  })

  it('should not detect namespace import as duplicate with named import', () => {
    const code = `import * as mod from 'module'
import { a } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Duplicate imports found')
  })

  it('should not detect type imports mixed with regular imports', () => {
    const code = `import { a } from 'module'
import type { B } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect duplicate type imports', () => {
    const code = `import type { A } from 'module'
import type { B } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Duplicate type imports found')
  })

  it('should detect duplicate imports with relative paths', () => {
    const code = `import { a } from './utils'
import { b } from './utils'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('./utils')
  })

  it('should detect duplicate imports with scoped packages', () => {
    const code = `import { a } from '@scope/package'
import { b } from '@scope/package'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('@scope/package')
  })

  it('should not detect single namespace import', () => {
    const code = `import * as mod from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect single default import', () => {
    const code = `import mod from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect duplicate imports in different scopes', () => {
    const code = `import { a } from 'module'
function test() {
  const x = a
}
import { b } from 'module'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Duplicate imports found')
  })
})