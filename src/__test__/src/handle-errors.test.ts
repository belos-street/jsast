import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('handle-errors rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('handle-errors')
  })

  it('should detect empty catch block', () => {
    const code = 'try { doSomething() } catch (e) {}'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Empty catch block found')
  })

  it('should detect empty catch block with error parameter', () => {
    const code = 'try { doSomething() } catch (error) {}'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Empty catch block found')
  })

  it('should not detect catch block with console.log', () => {
    const code = 'try { doSomething() } catch (e) { console.log(e) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect catch block with error handling', () => {
    const code = 'try { doSomething() } catch (e) { handleError(e) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect catch block with throw', () => {
    const code = 'try { doSomething() } catch (e) { throw e }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect catch block with return statement', () => {
    const code = 'try { doSomething() } catch (e) { return null }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect catch block with variable assignment', () => {
    const code = 'try { doSomething() } catch (e) { error = e }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple empty catch blocks', () => {
    const code = 'try { a() } catch (e) {} try { b() } catch (e) {}'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect try block without catch', () => {
    const code = 'try { doSomething() } finally { cleanup() }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect catch block with alert call', () => {
    const code = 'try { doSomething() } catch (e) { alert(e.message) }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect catch block with nested try-catch', () => {
    const code = 'try { doSomething() } catch (e) { try { handle(e) } catch (err) { console.log(err) } }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect empty catch block in nested function', () => {
    const code = 'function test() { try { doSomething() } catch (e) {} }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Empty catch block found')
  })

  it('should detect empty catch block in async function', () => {
    const code = 'async function test() { try { await doSomething() } catch (e) {} }'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Empty catch block found')
  })
})
