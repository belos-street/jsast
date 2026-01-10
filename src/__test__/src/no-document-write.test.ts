import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('no-document-write rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('no-document-write')
  })

  describe('document.write with dynamic content', () => {
    it('should detect document.write with variable', () => {
      const code = `
        const userInput = '<script>alert(1)</script>'
        document.write(userInput)
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.write')
    })

    it('should detect document.write with string concatenation', () => {
      const code = `
        const userInput = 'XSS'
        document.write('<div>' + userInput + '</div>')
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.write')
    })

    it('should detect document.write with template literal', () => {
      const code = `
        const userInput = 'test'
        document.write(\`<div>\${userInput}</div>\`)
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.write')
    })

    it('should detect document.write with function call', () => {
      const code = `
        function getHtml() {
          return '<div>content</div>'
        }
        document.write(getHtml())
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.write')
    })
  })

  describe('document.writeln with dynamic content', () => {
    it('should detect document.writeln with variable', () => {
      const code = `
        const userInput = '<script>alert(1)</script>'
        document.writeln(userInput)
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.writeln')
    })

    it('should detect document.writeln with string concatenation', () => {
      const code = `
        const userInput = 'XSS'
        document.writeln('<div>' + userInput + '</div>')
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.writeln')
    })

    it('should detect document.writeln with template literal', () => {
      const code = `
        const userInput = 'test'
        document.writeln(\`<div>\${userInput}</div>\`)
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('document.writeln')
    })
  })

  describe('document.write with static content', () => {
    it('should not detect document.write with static string', () => {
      const code = `
        document.write('<div>Static content</div>')
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect document.writeln with static string', () => {
      const code = `
        document.writeln('<div>Static content</div>')
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect document.write with plain text', () => {
      const code = `
        document.write('Hello World')
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('multiple document.write calls', () => {
    it('should detect multiple document.write calls', () => {
      const code = `
        const userInput1 = '<script>alert(1)</script>'
        const userInput2 = '<script>alert(2)</script>'
        document.write(userInput1)
        document.write(userInput2)
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should detect document.write and document.writeln together', () => {
      const code = `
        const userInput = '<script>alert(1)</script>'
        document.write(userInput)
        document.writeln(userInput)
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })
  })

  describe('other function calls', () => {
    it('should not detect other function calls', () => {
      const code = `
        console.log('test')
        alert('test')
        prompt('test')
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })
  })
})
