import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('use-secure-random rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('use-secure-random')
  })

  it('should detect Math.random() direct call', () => {
    const code = 'const token = Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
    expect(issues[0]!.message).toContain('crypto.randomBytes')
  })

  it('should detect Math.random() with toString', () => {
    const code = 'const token = Math.random().toString(36)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() with substring', () => {
    const code = 'const sessionId = Math.random().toString(36).substring(2)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in function call', () => {
    const code = 'console.log(Math.random())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in array', () => {
    const code = 'const arr = [1, 2, Math.random()]'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in object', () => {
    const code = 'const obj = { random: Math.random() }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in return statement', () => {
    const code = 'function getRandom() { return Math.random() }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in arrow function', () => {
    const code = 'const getRandom = () => Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in template literal', () => {
    const code = 'const str = `Random: ${Math.random()}`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should detect Math.random() in binary expression', () => {
    const code = 'const num = Math.random() * 100'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Math.random')
  })

  it('should not detect crypto.randomBytes()', () => {
    const code = 'const token = crypto.randomBytes(16).toString("hex")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect crypto.randomInt()', () => {
    const code = 'const num = crypto.randomInt(1, 100)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect crypto.randomUUID()', () => {
    const code = 'const id = crypto.randomUUID()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other Math methods', () => {
    const code = 'const num = Math.floor(10.5)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect Math.PI', () => {
    const code = 'const pi = Math.PI'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect Math.E', () => {
    const code = 'const e = Math.E'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect Math.random() multiple times', () => {
    const code = 'const a = Math.random(); const b = Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect Math.random() in loop', () => {
    const code = 'for (let i = 0; i < 10; i++) { console.log(Math.random()) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in conditional', () => {
    const code = 'if (Math.random() > 0.5) { console.log("heads") }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in ternary operator', () => {
    const code = 'const result = Math.random() > 0.5 ? "heads" : "tails"'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in logical expression', () => {
    const code = 'const result = Math.random() || 0'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in assignment', () => {
    const code = 'let num; num = Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in unary expression', () => {
    const code = 'const num = +Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in update expression', () => {
    const code = 'let num = Math.random(); num++'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in sequence expression', () => {
    const code = 'const num = (console.log("test"), Math.random())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in await expression', () => {
    const code = 'const num = await Promise.resolve(Math.random())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in spread element', () => {
    const code = 'const arr = [...[Math.random()]]'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in new expression', () => {
    const code = 'const num = new Number(Math.random())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in this expression context', () => {
    const code = 'this.random = Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in optional chaining', () => {
    const code = 'const num = obj?.random || Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in nullish coalescing', () => {
    const code = 'const num = obj?.random ?? Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in computed property', () => {
    const code = 'const obj = { [Math.random()]: "value" }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in function parameter', () => {
    const code = 'function getRandom(num = Math.random()) { return num }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in class method', () => {
    const code = 'class MyClass { getRandom() { return Math.random() } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in try-catch', () => {
    const code = 'try { const num = Math.random() } catch (e) {}'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in switch statement', () => {
    const code = 'switch (Math.random() > 0.5) { case true: console.log("heads"); break; }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in while loop', () => {
    const code = 'while (Math.random() > 0.5) { console.log("test") }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in do-while loop', () => {
    const code = 'do { console.log("test") } while (Math.random() > 0.5)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in for-in loop', () => {
    const code = 'for (const key in { a: Math.random() }) { console.log(key) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in for-of loop', () => {
    const code = 'for (const num of [Math.random()]) { console.log(num) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in with statement', () => {
    const code = 'with (Math) { const num = random() }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect Math.random() in labeled statement', () => {
    const code = 'label: { const num = Math.random() }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in debugger statement', () => {
    const code = 'debugger; const num = Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in throw statement', () => {
    const code = 'throw new Error(Math.random().toString())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in import.meta', () => {
    const code = 'const num = Math.random() + import.meta.url'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in super call', () => {
    const code = 'class Child extends Parent { constructor() { super(Math.random()) } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in yield expression', () => {
    const code = 'function* gen() { yield Math.random() }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Math.random() in yield* expression', () => {
    const code = 'function* gen() { yield* [Math.random()] }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })
})
