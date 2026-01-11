import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('validate-json-parse rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('validate-json-parse')
  })

  it('should detect JSON.parse with identifier argument', () => {
    const code = 'JSON.parse(userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
    expect(issues[0]!.message).toContain('unvalidated input')
  })

  it('should detect JSON.parse with member expression argument', () => {
    const code = 'JSON.parse(req.body)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with template literal argument', () => {
    const code = 'JSON.parse(`{"data": ${userInput}}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with binary expression argument', () => {
    const code = 'JSON.parse(prefix + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with call expression argument', () => {
    const code = 'JSON.parse(getUserInput())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should not detect JSON.parse with static string', () => {
    const code = 'JSON.parse(\'{"name": "test"}\')'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect JSON.parse with numeric literal', () => {
    const code = "JSON.parse('123')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect JSON.parse with boolean literal', () => {
    const code = "JSON.parse('true')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect JSON.parse with null literal', () => {
    const code = "JSON.parse('null')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect JSON.parse with array literal', () => {
    const code = "JSON.parse('[1, 2, 3]')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect JSON.parse with object literal', () => {
    const code = 'JSON.parse(\'{"key": "value"}\')'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect JSON.stringify', () => {
    const code = 'JSON.stringify(data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect JSON.parse with nested member expression', () => {
    const code = 'JSON.parse(request.query.data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with computed member expression', () => {
    const code = 'JSON.parse(obj[key])'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with conditional expression', () => {
    const code = 'JSON.parse(condition ? userInput : fallback)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with logical expression', () => {
    const code = 'JSON.parse(userInput || defaultData)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with spread element', () => {
    const code = 'JSON.parse(...args)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with new expression', () => {
    const code = 'JSON.parse(new String(userInput))'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with this expression', () => {
    const code = 'JSON.parse(this.data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with array expression', () => {
    const code = 'JSON.parse([userInput])'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with object expression', () => {
    const code = 'JSON.parse({ data: userInput })'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with function expression', () => {
    const code = 'JSON.parse(getData())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with arrow function', () => {
    const code = 'JSON.parse(() => userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with await expression', () => {
    const code = 'JSON.parse(await fetchUserInput())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with unary expression', () => {
    const code = 'JSON.parse(+userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with update expression', () => {
    const code = 'JSON.parse(counter++)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with sequence expression', () => {
    const code = 'JSON.parse((a, b, userInput))'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with assignment expression', () => {
    const code = 'JSON.parse(data = userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with tagged template expression', () => {
    const code = 'JSON.parse(tag`data${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with type cast expression', () => {
    const code = 'JSON.parse(userInput as string)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with JSX expression', () => {
    const code = 'JSON.parse(<Component />)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with class expression', () => {
    const code = 'JSON.parse(class MyClass {} )'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with meta property', () => {
    const code = 'JSON.parse(import.meta.url)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with import expression', () => {
    const code = 'JSON.parse(import("./data"))'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with optional chaining', () => {
    const code = 'JSON.parse(obj?.data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })

  it('should detect JSON.parse with nullish coalescing', () => {
    const code = 'JSON.parse(obj?.data ?? defaultData)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('JSON.parse')
  })
})
