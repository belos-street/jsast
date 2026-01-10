import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-unsafe-fs-access rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-unsafe-fs-access')
  })

  it('should detect fs.readFile with template literal', () => {
    const code = 'fs.readFile(`./data/${userInput}.txt`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Unsafe file system access')
    expect(issues[0]!.message).toContain('readFile')
  })

  it('should detect fs.writeFile with binary expression', () => {
    const code = 'fs.writeFile("./output/" + fileName, data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('writeFile')
  })

  it('should detect fs.unlink with template literal', () => {
    const code = 'fs.unlink(`./temp/${id}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('unlink')
  })

  it('should detect fs.mkdir with template literal', () => {
    const code = 'fs.mkdir(`./logs/${date}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('mkdir')
  })

  it('should detect fs.rmdir with binary expression', () => {
    const code = 'fs.rmdir("./cache/" + cacheId)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rmdir')
  })

  it('should detect fs.readdir with template literal', () => {
    const code = 'fs.readdir(`./uploads/${userId}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readdir')
  })

  it('should detect fs.stat with template literal', () => {
    const code = 'fs.stat(`./files/${filename}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('stat')
  })

  it('should detect fs.existsSync with binary expression', () => {
    const code = 'fs.existsSync("./data/" + path)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('existsSync')
  })

  it('should detect require fs.readFile with template literal', () => {
    const code = "require('fs').readFile(`./data/${userInput}.txt`)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain("require('fs')")
  })

  it('should detect require fs.writeFile with binary expression', () => {
    const code = "require('fs').writeFile('./output/' + fileName, data)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('writeFile')
  })

  it('should detect direct readFile call with template literal', () => {
    const code = 'readFile(`./data/${userInput}.txt`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readFile')
  })

  it('should detect fs.appendFile with template literal', () => {
    const code = 'fs.appendFile(`./logs/${date}.log`, message)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('appendFile')
  })

  it('should detect fs.rename with template literal (both paths)', () => {
    const code = 'fs.rename(`./old/${oldName}`, `./new/${newName}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect fs.copyFile with template literal (both paths)', () => {
    const code = 'fs.copyFile(`./src/${srcFile}`, `./dst/${dstFile}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should not detect fs.readFile with static string', () => {
    const code = "fs.readFile('./data/config.txt')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect fs.writeFile with static string', () => {
    const code = "fs.writeFile('./output/result.txt', data)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect fs.unlink with static string', () => {
    const code = "fs.unlink('./temp/file.txt')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect fs.mkdir with static string', () => {
    const code = "fs.mkdir('./logs')"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple unsafe fs calls', () => {
    const code = 'fs.readFile(`./data/${x}`); fs.writeFile("./out/" + y, data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect fs.unlinkSync with template literal', () => {
    const code = 'fs.unlinkSync(`./temp/${id}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('unlinkSync')
  })

  it('should detect fs.readFileSync with binary expression', () => {
    const code = 'fs.readFileSync("./data/" + path)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readFileSync')
  })

  it('should detect fs.writeFileSync with template literal', () => {
    const code = 'fs.writeFileSync(`./output/${filename}`, data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('writeFileSync')
  })

  it('should detect fs.mkdirSync with template literal', () => {
    const code = 'fs.mkdirSync(`./logs/${date}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('mkdirSync')
  })

  it('should detect fs.rmdirSync with binary expression', () => {
    const code = 'fs.rmdirSync("./cache/" + id)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rmdirSync')
  })

  it('should detect fs.readdirSync with template literal', () => {
    const code = 'fs.readdirSync(`./uploads/${userId}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readdirSync')
  })

  it('should detect fs.statSync with template literal', () => {
    const code = 'fs.statSync(`./files/${filename}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('statSync')
  })

  it('should detect fs.renameSync with template literal (both paths)', () => {
    const code = 'fs.renameSync(`./old/${oldName}`, `./new/${newName}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect fs.copyFileSync with template literal (both paths)', () => {
    const code = 'fs.copyFileSync(`./src/${srcFile}`, `./dst/${dstFile}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })
})
