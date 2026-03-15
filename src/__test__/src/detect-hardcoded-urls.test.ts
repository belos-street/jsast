import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('detect-hardcoded-urls rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('detect-hardcoded-urls')
  })

  it('should detect hardcoded HTTP URL', () => {
    const code = "const apiUrl = 'http://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
    expect(issues[0]!.message).toContain('URL')
  })

  it('should detect hardcoded HTTPS URL', () => {
    const code = "const apiUrl = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
    expect(issues[0]!.message).toContain('URL')
  })

  it('should detect hardcoded API endpoint', () => {
    const code = "const endpoint = 'https://api.github.com/users'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded database URL', () => {
    const code = "const dbUrl = 'mongodb://localhost:27017/mydb'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded Redis URL', () => {
    const code = "const redisUrl = 'redis://localhost:6379'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded FTP URL', () => {
    const code = "const ftpUrl = 'ftp://example.com/files'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded SFTP URL', () => {
    const code = "const sftpUrl = 'sftp://example.com/files'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded WebSocket URL', () => {
    const code = "const wsUrl = 'ws://example.com/socket'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded secure WebSocket URL', () => {
    const code = "const wssUrl = 'wss://example.com/socket'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded URL with port', () => {
    const code = "const apiUrl = 'https://api.example.com:8080'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded URL with path', () => {
    const code = "const apiUrl = 'https://api.example.com/v1/users'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded URL with query parameters', () => {
    const code = "const apiUrl = 'https://api.example.com/users?id=123'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded URL in object property', () => {
    const code = "const config = { apiUrl: 'https://api.example.com' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded URL in array', () => {
    const code = "const urls = ['https://api.example.com', 'https://backup.example.com']"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded URL in function call', () => {
    const code = "fetch('https://api.example.com/data')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded URL in template literal', () => {
    const code = 'const apiUrl = `https://api.example.com`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded localhost URL', () => {
    const code = "const apiUrl = 'http://localhost:3000'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded 127.0.0.1 URL', () => {
    const code = "const apiUrl = 'http://127.0.0.1:3000'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should detect hardcoded 0.0.0.0 URL', () => {
    const code = "const apiUrl = 'http://0.0.0.0:3000'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('hardcoded')
  })

  it('should not detect environment variable usage', () => {
    const code = 'const apiUrl = process.env.API_URL'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect environment variable in template literal', () => {
    const code = 'const apiUrl = `${process.env.API_URL}`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect empty string', () => {
    const code = "const apiUrl = ''"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect short strings', () => {
    const code = "const apiUrl = 'http'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect relative paths', () => {
    const code = "const apiUrl = '/api/users'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect file:// protocol', () => {
    const code = "const fileUrl = 'file:///path/to/file'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect data: URLs', () => {
    const code = "const dataUrl = 'data:text/plain;base64,SGVsbG8='"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect mailto: URLs', () => {
    const code = "const email = 'mailto:user@example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect tel: URLs', () => {
    const code = "const phone = 'tel:+1234567890'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect javascript: URLs', () => {
    const code = "const jsUrl = 'javascript:void(0)'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect about: URLs', () => {
    const code = "const aboutUrl = 'about:blank'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect common placeholder values', () => {
    const code = "const apiUrl = 'your-api-url-here'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect example.com in comments', () => {
    const code = "// const apiUrl = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple hardcoded URLs in same file', () => {
    const code = `
      const apiUrl = 'https://api.example.com'
      const dbUrl = 'mongodb://localhost:27017/mydb'
      const wsUrl = 'wss://example.com/socket'
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(3)
  })

  it('should detect hardcoded URL in export', () => {
    const code = "export const API_URL = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in default export', () => {
    const code = "export default { apiUrl: 'https://api.example.com' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in class property', () => {
    const code = `
      class ApiClient {
        baseUrl = 'https://api.example.com'
      }
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in class method', () => {
    const code = `
      class ApiClient {
        getUrl() {
          return 'https://api.example.com'
        }
      }
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in arrow function', () => {
    const code = "const getUrl = () => 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in conditional', () => {
    const code = `
      const isProd = true
      const apiUrl = isProd ? 'https://api.example.com' : 'http://localhost:3000'
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded URL in switch', () => {
    const code = `
      function getApiUrl(env) {
        switch (env) {
          case 'prod':
            return 'https://api.example.com'
          case 'dev':
            return 'http://localhost:3000'
        }
      }
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded URL in try-catch', () => {
    const code = `
      try {
        const apiUrl = 'https://api.example.com'
      } catch (error) {
        console.error(error)
      }
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in async function', () => {
    const code = `
      async function fetchData() {
        const apiUrl = 'https://api.example.com'
        return fetch(apiUrl)
      }
    `
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in await expression', () => {
    const code = "const data = await fetch('https://api.example.com/data')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in new expression', () => {
    const code = "const client = new WebSocket('ws://example.com/socket')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in computed property', () => {
    const code = "const config = { ['apiUrl']: 'https://api.example.com' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in default parameter', () => {
    const code = "function fetch(url = 'https://api.example.com') {}"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in throw statement', () => {
    const code = "throw new Error('Invalid URL: https://api.example.com')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in yield expression', () => {
    const code = "function* getUrl() { yield 'https://api.example.com' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in yield* expression', () => {
    const code = "function* getUrls() { yield* ['https://api.example.com'] }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in this expression', () => {
    const code = "this.apiUrl = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in sequence expression', () => {
    const code = "(x = 'https://api.example.com', x)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in update expression', () => {
    const code = "const urls = ['https://api.example.com']"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in unary expression', () => {
    const code = "const url = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in logical expression', () => {
    const code = "const apiUrl = 'https://api.example.com' || 'https://backup.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded URL in optional chaining', () => {
    const code = "const url = config?.apiUrl || 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded URL in nullish coalescing', () => {
    const code = "const apiUrl = config?.apiUrl ?? 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })
})
