import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('detect-prototype-pollution rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('detect-prototype-pollution')
  })

  it('should detect Object.prototype assignment', () => {
    const code = 'Object.prototype[key] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect __proto__ assignment', () => {
    const code = 'obj.__proto__ = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect constructor.prototype assignment', () => {
    const code = 'obj.constructor.prototype[key] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.assign with __proto__', () => {
    const code = 'Object.assign(target, { __proto__: malicious })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.defineProperty with __proto__', () => {
    const code = 'Object.defineProperty(obj, "__proto__", { value: malicious })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.create with __proto__', () => {
    const code = 'Object.create({ __proto__: malicious })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.setPrototypeOf with untrusted input', () => {
    const code = 'Object.setPrototypeOf(obj, maliciousInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Reflect.defineProperty with __proto__', () => {
    const code = 'Reflect.defineProperty(obj, "__proto__", { value: malicious })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect lodash.merge with untrusted input', () => {
    const code = 'lodash.merge(target, userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect _.merge with untrusted input', () => {
    const code = '_.merge(target, userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect jQuery.extend with untrusted input', () => {
    const code = 'jQuery.extend(target, userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect $.extend with untrusted input', () => {
    const code = '$.extend(target, userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect spread operator with __proto__ property', () => {
    const code = 'const result = { ...target, ...{ __proto__: malicious } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.assign with computed __proto__', () => {
    const code = 'Object.assign(target, { [key]: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should not detect safe Object.assign', () => {
    const code = 'Object.assign(target, { name: "test" })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe property assignment', () => {
    const code = 'obj.name = "test"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe Object.defineProperty', () => {
    const code = 'Object.defineProperty(obj, "name", { value: "test" })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe Object.create', () => {
    const code = 'Object.create(null)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe Object.setPrototypeOf', () => {
    const code = 'Object.setPrototypeOf(obj, null)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe Reflect.defineProperty', () => {
    const code = 'Reflect.defineProperty(obj, "name", { value: "test" })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe lodash.merge', () => {
    const code = 'lodash.merge(target, { name: "test" })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe jQuery.extend', () => {
    const code = 'jQuery.extend(target, { name: "test" })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect safe spread operator', () => {
    const code = 'const result = { ...target, ...{ name: "test" } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect Object.prototype assignment with computed property', () => {
    const code = 'Object.prototype[userKey] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect __proto__ assignment with computed property', () => {
    const code = 'obj["__proto__"] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect constructor.prototype assignment with computed property', () => {
    const code = 'obj.constructor.prototype[userKey] = value'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect merge function with nested __proto__', () => {
    const code = 'lodash.merge(target, { nested: { __proto__: malicious } })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect merge function with constructor property', () => {
    const code = 'lodash.merge(target, { constructor: { prototype: malicious } })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect merge function with prototype property', () => {
    const code = 'lodash.merge(target, { prototype: malicious })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should not detect safe merge function', () => {
    const code = 'lodash.merge(target, { name: "test", age: 25 })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect Object.assign with template literal key', () => {
    const code = 'Object.assign(target, { [`${key}`]: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.assign with binary expression key', () => {
    const code = 'Object.assign(target, { [prefix + key]: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })

  it('should detect Object.assign with call expression key', () => {
    const code = 'Object.assign(target, { [getKey()]: value })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('prototype pollution')
  })
})
