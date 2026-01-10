import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-unsafe-html rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-unsafe-html')
  })

  describe('Express res.send with dynamic HTML', () => {
    it('should detect res.send with string concatenation', () => {
      const code = `
        app.get('/user', (req, res) => {
          const userInput = req.query.name
          res.send('<div>' + userInput + '</div>')
        })
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('XSS')
    })

    it('should detect res.send with template literal', () => {
      const code = `
        app.get('/user', (req, res) => {
          const userInput = req.query.name
          res.send(\`<div>\${userInput}</div>\`)
        })
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect res.send with variable', () => {
      const code = `
        app.get('/user', (req, res) => {
          const html = '<div>' + userInput + '</div>'
          res.send(html)
        })
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect res.send with function call', () => {
      const code = `
        app.get('/user', (req, res) => {
          res.send(generateHtml(req.query.name))
        })
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should not detect res.send with static HTML', () => {
      const code = `
        app.get('/user', (req, res) => {
          res.send('<div>Static content</div>')
        })
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect res.send with plain text', () => {
      const code = `
        app.get('/user', (req, res) => {
          res.send('Hello World')
        })
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('React JSX with unescaped content', () => {
    it('should detect JSX with variable content', () => {
      const code = `
        function UserComponent({ userInput }) {
          return <div>{userInput}</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(1)
    })

    it('should detect JSX with object property', () => {
      const code = `
        function UserComponent({ user }) {
          return <div>{user.name}</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(1)
    })

    it('should detect JSX with function call', () => {
      const code = `
        function UserComponent() {
          return <div>{getData()}</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(1)
    })

    it('should detect JSX with template literal', () => {
      const code = `
        function UserComponent({ userInput }) {
          return <div>\`Hello \${userInput}\`</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(1)
    })

    it('should detect nested JSX with dynamic content', () => {
      const code = `
        function UserComponent({ userInput }) {
          return (
            <div>
              <span>{userInput}</span>
            </div>
          )
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBeGreaterThanOrEqual(1)
    })

    it('should not detect JSX with static content', () => {
      const code = `
        function UserComponent() {
          return <div>Static content</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect JSX with number', () => {
      const code = `
        function UserComponent() {
          return <div>{42}</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect JSX with boolean', () => {
      const code = `
        function UserComponent({ isActive }) {
          return <div>{isActive ? 'Active' : 'Inactive'}</div>
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.tsx', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('Other unsafe HTML generation patterns', () => {
    it('should detect document.write with dynamic content', () => {
      const code = `
        function render(userInput) {
          document.write('<div>' + userInput + '</div>')
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect outerHTML assignment', () => {
      const code = `
        function render(userInput) {
          const element = document.getElementById('container')
          element.outerHTML = '<div>' + userInput + '</div>'
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect insertAdjacentHTML', () => {
      const code = `
        function render(userInput) {
          const element = document.getElementById('container')
          element.insertAdjacentHTML('beforeend', '<div>' + userInput + '</div>')
        }
      `
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })
})
