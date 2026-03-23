import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('prevent-prototype-pollution rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('prevent-prototype-pollution')
  })

  it('should detect assignment to __proto__', () => {
    const code = "obj['__proto__'] = value"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Prototype pollution detected')
    expect(issues[0]!.message).toContain('__proto__')
  })

  it('should detect assignment to __proto__ with string literal', () => {
    const code = 'obj["__proto__"] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Prototype pollution detected')
  })

  it('should detect assignment to constructor.prototype', () => {
    const code = 'constructor.prototype = {}'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype')
  })

  it('should detect Object.assign with __proto__', () => {
    const code = "Object.assign(obj, { '__proto__': value })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Object.assign')
    expect(issues[0]!.message).toContain('__proto__')
  })

  it('should detect Object.assign with constructor', () => {
    const code = 'Object.assign(obj, { constructor: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Object.assign')
    expect(issues[0]!.message).toContain('constructor')
  })

  it('should detect Object.assign with prototype', () => {
    const code = 'Object.assign(obj, { prototype: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Object.assign')
    expect(issues[0]!.message).toContain('prototype')
  })

  it('should detect merge function with __proto__', () => {
    const code = "merge(obj, { '__proto__': value })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('merge')
    expect(issues[0]!.message).toContain('__proto__')
  })

  it('should not detect safe object assignment', () => {
    const code = 'obj.name = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect Object.assign with safe properties', () => {
    const code = "Object.assign(obj, { name: 'value', age: 25 })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect Object.assign with identifier keys', () => {
    const code = 'const key = "name"; Object.assign(obj, { [key]: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect assignment to obj.prototype', () => {
    const code = 'obj.prototype = {}'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype')
  })

  it('should detect multiple dangerous assignments', () => {
    const code = "obj['__proto__'] = 1; obj['constructor'] = 2"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect normal function calls', () => {
    const code = 'console.log("hello")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect Object.merge with __proto__', () => {
    const code = "Object.merge(obj, { '__proto__': value })"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Object.merge')
  })

  it('should not detect assignment to nested safe property', () => {
    const code = "obj['__proto__']['test'] = value"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })
})
