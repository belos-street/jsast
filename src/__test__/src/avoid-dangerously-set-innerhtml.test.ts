import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-dangerously-set-innerhtml rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-dangerously-set-innerhtml')
  })

  describe('Direct innerHTML assignment', () => {
    it('should detect element.innerHTML = userInput', () => {
      const code = 'element.innerHTML = userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('innerHTML')
      expect(issues[0]!.message).toContain('XSS')
    })

    it('should detect document.getElementById().innerHTML = data', () => {
      const code = "document.getElementById('app').innerHTML = data"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect document.querySelector().innerHTML = content', () => {
      const code = "document.querySelector('.container').innerHTML = content"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect div.innerHTML = html', () => {
      const code = 'div.innerHTML = html'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Template literal innerHTML assignment', () => {
    it('should detect innerHTML with template literal containing variable', () => {
      const code = 'element.innerHTML = `<div>${userInput}</div>`'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect innerHTML with template literal containing function call', () => {
      const code = 'element.innerHTML = `<div>${getUserData()}</div>`'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('String concatenation innerHTML assignment', () => {
    it('should detect innerHTML with string concatenation', () => {
      const code = 'element.innerHTML = "<div>" + userInput + "</div>"'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect innerHTML with multiple concatenations', () => {
      const code = 'element.innerHTML = "<div>" + title + "</div><p>" + content + "</p>"'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('React dangerouslySetInnerHTML', () => {
    it('should detect dangerouslySetInnerHTML with user input', () => {
      const code = '<div dangerouslySetInnerHTML={{ __html: userInput }} />'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.jsx', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('dangerouslySetInnerHTML')
    })

    it('should detect dangerouslySetInnerHTML with template literal', () => {
      const code = '<div dangerouslySetInnerHTML={{ __html: `<div>${userInput}</div>` }} />'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.jsx', code)
      expect(issues.length).toBe(1)
    })

    it('should detect dangerouslySetInnerHTML with string concatenation', () => {
      const code = '<div dangerouslySetInnerHTML={{ __html: "<div>" + userInput + "</div>" }} />'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.jsx', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Safe patterns', () => {
    it('should not detect innerHTML with static string', () => {
      const code = 'element.innerHTML = "<div>Static content</div>"'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect innerHTML with empty string', () => {
      const code = 'element.innerHTML = ""'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect textContent assignment', () => {
      const code = 'element.textContent = userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect innerText assignment', () => {
      const code = 'element.innerText = userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect dangerouslySetInnerHTML with static string', () => {
      const code = '<div dangerouslySetInnerHTML={{ __html: "<div>Static content</div>" }} />'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.jsx', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('Edge cases', () => {
    it('should detect innerHTML assignment in nested object', () => {
      const code = 'container.element.innerHTML = userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect innerHTML assignment with computed property', () => {
      const code = 'elements[0].innerHTML = userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect innerHTML assignment with call expression', () => {
      const code = 'getElement().innerHTML = userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect innerHTML += operator', () => {
      const code = 'element.innerHTML += userInput'
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Multiple violations', () => {
    it('should detect multiple innerHTML assignments', () => {
      const code = `
        element.innerHTML = userInput
        document.getElementById('app').innerHTML = data
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should detect innerHTML and dangerouslySetInnerHTML', () => {
      const code1 = 'element.innerHTML = userInput'
      const issues1: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code1)

      const code2 = '<div dangerouslySetInnerHTML={{ __html: data }} />'
      const issues2: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.jsx', code2)

      expect(issues1.length).toBe(1)
      expect(issues2.length).toBe(1)
    })
  })
})
