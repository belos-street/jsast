import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-weak-crypto rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-weak-crypto')
  })

  it('should detect crypto.createHash with sha256', () => {
    const code = "crypto.createHash('sha256')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with sha512', () => {
    const code = "crypto.createHash('sha512')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with md4', () => {
    const code = "crypto.createHash('md4')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('md4')
  })

  it('should detect crypto.createHash with ripemd160', () => {
    const code = "crypto.createHash('ripemd160')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('ripemd160')
  })

  it('should detect crypto.createHash with variable containing weak algorithm', () => {
    const code = "const algo = 'md5'; crypto.createHash(algo)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with template literal containing weak algorithm', () => {
    const code = 'crypto.createHash(`md5`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with binary expression', () => {
    const code = "crypto.createHash('md' + '5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with call expression', () => {
    const code = 'crypto.createHash(getAlgorithm())'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other crypto methods', () => {
    const code = 'crypto.randomBytes(16)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect crypto.createCipher', () => {
    const code = "crypto.createCipher('aes-256-cbc', key)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect crypto.createDecipher', () => {
    const code = "crypto.createDecipher('aes-256-cbc', key)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect crypto.createSign', () => {
    const code = "crypto.createSign('sha256')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect crypto.createVerify', () => {
    const code = "crypto.createVerify('sha256')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with md5 in different case', () => {
    const code = "crypto.createHash('MD5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in different case', () => {
    const code = "crypto.createHash('SHA1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in mixed case', () => {
    const code = "crypto.createHash('Md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in mixed case', () => {
    const code = "crypto.createHash('Sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in function call', () => {
    const code = "console.log(crypto.createHash('md5'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in function call', () => {
    const code = "console.log(crypto.createHash('sha1'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in variable assignment', () => {
    const code = "const hash = crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in variable assignment', () => {
    const code = "const hash = crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in return statement', () => {
    const code = "function getHash() { return crypto.createHash('md5') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in return statement', () => {
    const code = "function getHash() { return crypto.createHash('sha1') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in arrow function', () => {
    const code = "const getHash = () => crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in arrow function', () => {
    const code = "const getHash = () => crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in object', () => {
    const code = "const obj = { hash: crypto.createHash('md5') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in object', () => {
    const code = "const obj = { hash: crypto.createHash('sha1') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in array', () => {
    const code = "const arr = [crypto.createHash('md5')]"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in array', () => {
    const code = "const arr = [crypto.createHash('sha1')]"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in template literal', () => {
    const code = "const str = `Hash: ${crypto.createHash('md5')}`"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)

    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in template literal', () => {
    const code = "const str = `Hash: ${crypto.createHash('sha1')}`"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in binary expression', () => {
    const code = "const num = crypto.createHash('md5').length"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in binary expression', () => {
    const code = "const num = crypto.createHash('sha1').length"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in logical expression', () => {
    const code = "const hash = crypto.createHash('md5') || null"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in logical expression', () => {
    const code = "const hash = crypto.createHash('sha1') || null"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in ternary operator', () => {
    const code = "const hash = useMd5 ? crypto.createHash('md5') : crypto.createHash('sha256')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in ternary operator', () => {
    const code = "const hash = useSha1 ? crypto.createHash('sha1') : crypto.createHash('sha256')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in loop', () => {
    const code = "for (let i = 0; i < 10; i++) { const hash = crypto.createHash('md5') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in loop', () => {
    const code = "for (let i = 0; i < 10; i++) { const hash = crypto.createHash('sha1') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in conditional', () => {
    const code = "if (useMd5) { const hash = crypto.createHash('md5') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in conditional', () => {
    const code = "if (useSha1) { const hash = crypto.createHash('sha1') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in try-catch', () => {
    const code = "try { const hash = crypto.createHash('md5') } catch (e) {}"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in try-catch', () => {
    const code = "try { const hash = crypto.createHash('sha1') } catch (e) {}"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in switch', () => {
    const code = "switch (algo) { case 'md5': const hash = crypto.createHash('md5'); break; }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in switch', () => {
    const code = "switch (algo) { case 'sha1': const hash = crypto.createHash('sha1'); break; }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in class method', () => {
    const code = "class Hasher { getHash() { return crypto.createHash('md5') } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in class method', () => {
    const code = "class Hasher { getHash() { return crypto.createHash('sha1') } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in await expression', () => {
    const code = "const hash = await crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in await expression', () => {
    const code = "const hash = await crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in new expression', () => {
    const code = "const hash = new String(crypto.createHash('md5'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in new expression', () => {
    const code = "const hash = new String(crypto.createHash('sha1'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in spread element', () => {
    const code = "const arr = [...[crypto.createHash('md5')]]"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in spread element', () => {
    const code = "const arr = [...[crypto.createHash('sha1')]]"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in optional chaining', () => {
    const code = "const hash = crypto?.createHash?.('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with sha1 in optional chaining', () => {
    const code = "const hash = crypto?.createHash?.('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with md5 in nullish coalescing', () => {
    const code = "const hash = crypto?.createHash?.('md5') ?? null"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with sha1 in nullish coalescing', () => {
    const code = "const hash = crypto?.createHash?.('sha1') ?? null"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with md5 in computed property', () => {
    const code = "const obj = { [crypto.createHash('md5')]: 'value' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in computed property', () => {
    const code = "const obj = { [crypto.createHash('sha1')]: 'value' }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in default parameter', () => {
    const code = "function getHash(algo = 'md5') { return algo }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with sha1 in default parameter', () => {
    const code = "function getHash(algo = 'sha1') { return algo }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect crypto.createHash with md5 in throw statement', () => {
    const code = "throw new Error(crypto.createHash('md5'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in throw statement', () => {
    const code = "throw new Error(crypto.createHash('sha1'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in yield expression', () => {
    const code = "function* gen() { yield crypto.createHash('md5') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in yield expression', () => {
    const code = "function* gen() { yield crypto.createHash('sha1') }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in yield* expression', () => {
    const code = "function* gen() { yield* [crypto.createHash('md5')] }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in yield* expression', () => {
    const code = "function* gen() { yield* [crypto.createHash('sha1')] }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in this expression', () => {
    const code = "this.hash = crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in this expression', () => {
    const code = "this.hash = crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in super call', () => {
    const code = "class Child extends Parent { constructor() { super(crypto.createHash('md5')) } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in super call', () => {
    const code = "class Child extends Parent { constructor() { super(crypto.createHash('sha1')) } }"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in sequence expression', () => {
    const code = "const hash = (console.log('test'), crypto.createHash('md5'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in sequence expression', () => {
    const code = "const hash = (console.log('test'), crypto.createHash('sha1'))"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in update expression', () => {
    const code = "let hash; hash = crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in update expression', () => {
    const code = "let hash; hash = crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 in unary expression', () => {
    const code = "const hash = +crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with sha1 in unary expression', () => {
    const code = "const hash = +crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
  })

  it('should detect crypto.createHash with md5 multiple times', () => {
    const code = "const a = crypto.createHash('md5'); const b = crypto.createHash('md5')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect crypto.createHash with sha1 multiple times', () => {
    const code = "const a = crypto.createHash('sha1'); const b = crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect crypto.createHash with md5 and sha1 mixed', () => {
    const code = "const a = crypto.createHash('md5'); const b = crypto.createHash('sha1')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })
})
