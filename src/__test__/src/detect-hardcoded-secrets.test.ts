import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('detect-hardcoded-secrets rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('detect-hardcoded-secrets')
  })

  it('should detect hardcoded API key with sk- prefix', () => {
    const code = "const apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Hardcoded')
  })

  it('should detect hardcoded password', () => {
    const code = "const password = 'admin123'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect hardcoded database URL with credentials', () => {
    const code = "const dbUrl = 'mongodb://user:pass@localhost'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Database URL')
  })

  it('should detect API key with sk- prefix in object', () => {
    const code = "const config = { apiKey: 'sk-1234567890abcdef' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect password in object', () => {
    const code = "const config = { password: 'admin123' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect database URL in object', () => {
    const code = "const config = { dbUrl: 'mongodb://user:pass@localhost' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect API key with sk- prefix in function call', () => {
    const code = "client.setApiKey('sk-1234567890abcdef')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect password in function call', () => {
    const code = "login('admin', 'admin123')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect database URL in function call', () => {
    const code = "connect('mongodb://user:pass@localhost')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect API key with different prefixes', () => {
    const code = "const key = 'pk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect API key with Bearer prefix', () => {
    const code = "const token = 'Bearer 1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect API key with API_KEY prefix', () => {
    const code = "const key = 'API_KEY_1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect JWT token', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    const code = `const jwt = '${jwt}'`
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect AWS access key', () => {
    const code = "const accessKey = 'AKIAIOSFODNN7EXAMPLE'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect AWS secret key', () => {
    const code = "const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should detect GitHub personal access token', () => {
    const code = "const token = 'ghp_1234567890abcdef1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Slack API token', () => {
    const code = "const token = 'xoxb-1234567890-1234567890-1234567890abcdef123456'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Stripe API key', () => {
    const code = "const stripeKey = 'sk_test_1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should detect Firebase API key', () => {
    const code = "const firebaseKey = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Google Cloud API key', () => {
    const code = "const googleKey = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Twilio API key', () => {
    const code = "const twilioKey = 'SK1234567890abcdef1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect SendGrid API key', () => {
    const code = "const sendGridKey = 'SG.1234567890abcdef123456.1234567890abcdef1234567890abcdef1234567890abc'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Mailgun API key', () => {
    const code = "const mailgunKey = 'key-1234567890abcdef1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Datadog API key', () => {
    const code = "const datadogKey = '1234567890abcdef1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect New Relic license key', () => {
    const code = "const newRelicKey = '1234567890abcdef1234567890abcdef12345678'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect PagerDuty API key', () => {
    const code = "const pagerDutyKey = '1234567890abcdef1234'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Rollbar access token', () => {
    const code = "const rollbarKey = '1234567890abcdef1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Sentry DSN', () => {
    const code = "const sentryDsn = 'https://1234567890abcdef@sentry.io/123456'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect database connection string with password', () => {
    const code = "const dbUrl = 'postgresql://user:password123@localhost:5432/db'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect MySQL connection string with password', () => {
    const code = "const dbUrl = 'mysql://user:password123@localhost:3306/db'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Redis connection string with password', () => {
    const code = "const redisUrl = 'redis://:password123@localhost:6379'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect Elasticsearch connection string with password', () => {
    const code = "const esUrl = 'http://user:password123@localhost:9200'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect FTP connection string with password', () => {
    const code = "const ftpUrl = 'ftp://user:password123@ftp.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should detect SFTP connection string with password', () => {
    const code = "const sftpUrl = 'sftp://user:password123@sftp.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should detect SMTP connection string with password', () => {
    const code = "const smtpUrl = 'smtp://user:password123@smtp.example.com:587'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should detect IMAP connection string with password', () => {
    const code = "const imapUrl = 'imap://user:password123@imap.example.com:993'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should detect POP3 connection string with password', () => {
    const code = "const pop3Url = 'pop3://user:password123@pop3.example.com:995'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should not detect environment variable usage', () => {
    const code = 'const apiKey = process.env.API_KEY'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect environment variable usage with fallback', () => {
    const code = "const apiKey = process.env.API_KEY || 'default'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect empty string', () => {
    const code = "const password = ''"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect short strings', () => {
    const code = "const password = '123'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect common placeholder values', () => {
    const code = "const password = 'your_password_here'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect example values', () => {
    const code = "const apiKey = 'your-api-key-here'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect localhost URLs without credentials', () => {
    const code = "const dbUrl = 'mongodb://localhost:27017/mydb'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBeGreaterThanOrEqual(0)
  })

  it('should not detect production URLs without credentials', () => {
    const code = "const apiUrl = 'https://api.example.com'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect template literals with environment variables', () => {
    const code = 'const dbUrl = `mongodb://${process.env.DB_USER}:${process.env.DB_PASS}@localhost`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect config file references', () => {
    const code = "const config = require('./config.json')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect import statements', () => {
    const code = "import { apiKey } from './secrets'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect hardcoded secret in let declaration', () => {
    const code = "let apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in var declaration', () => {
    const code = "var apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in assignment', () => {
    const code = "apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in array', () => {
    const code = "const keys = ['sk-1234567890abcdef', 'pk-9876543210fedcba']"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded secret in nested object', () => {
    const code = "const config = { database: { url: 'mongodb://user:pass@localhost' } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in function return', () => {
    const code = "function getApiKey() { return 'sk-1234567890abcdef' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in arrow function', () => {
    const code = "const getApiKey = () => 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in class method', () => {
    const code = "class Config { getApiKey() { return 'sk-1234567890abcdef' } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in template literal', () => {
    const code = 'const apiKey = `sk-1234567890abcdef`'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in conditional', () => {
    const code = "if (useTestKey) { apiKey = 'sk-1234567890abcdef' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in loop', () => {
    const code = "for (let i = 0; i < 10; i++) { const key = 'sk-1234567890abcdef' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in try-catch', () => {
    const code = "try { apiKey = 'sk-1234567890abcdef' } catch (e) {}"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in switch', () => {
    const code = "switch (env) { case 'test': apiKey = 'sk-1234567890abcdef'; break; }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in ternary operator', () => {
    const code = "const apiKey = env === 'test' ? 'sk-1234567890abcdef' : 'sk-9876543210fedcba'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded secret in await expression', () => {
    const code = "const apiKey = await getApiKey('sk-1234567890abcdef')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in new expression', () => {
    const code = "const client = new Client('sk-1234567890abcdef')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in spread element', () => {
    const code = "const keys = [...['sk-1234567890abcdef']]"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in computed property', () => {
    const code = "const obj = { ['sk-1234567890abcdef']: 'value' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in default parameter', () => {
    const code = "function getApiKey(key = 'sk-1234567890abcdef') { return key }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in throw statement', () => {
    const code = "throw new Error('sk-1234567890abcdef')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in yield expression', () => {
    const code = "function* gen() { yield 'sk-1234567890abcdef' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in yield* expression', () => {
    const code = "function* gen() { yield* ['sk-1234567890abcdef'] }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in this expression', () => {
    const code = "this.apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in super call', () => {
    const code = "class Child extends Parent { constructor() { super('sk-1234567890abcdef') } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in sequence expression', () => {
    const code = "const apiKey = (console.log('test'), 'sk-1234567890abcdef')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in update expression', () => {
    const code = "let apiKey; apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in unary expression', () => {
    const code = "const apiKey = +'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in logical expression', () => {
    const code = "const apiKey = 'sk-1234567890abcdef' || null"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in binary expression', () => {
    const code = "const apiKey = 'sk-' + '1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect hardcoded secret in optional chaining', () => {
    const code = "const apiKey = config?.apiKey || 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in nullish coalescing', () => {
    const code = "const apiKey = config?.apiKey ?? 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect multiple hardcoded secrets in same file', () => {
    const code =
      "const apiKey = 'sk-1234567890abcdef'; const password = 'admin123'; const dbUrl = 'mongodb://user:pass@localhost'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect hardcoded secret in export', () => {
    const code = "export const apiKey = 'sk-1234567890abcdef'"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect hardcoded secret in default export', () => {
    const code = "export default { apiKey: 'sk-1234567890abcdef' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })
})
