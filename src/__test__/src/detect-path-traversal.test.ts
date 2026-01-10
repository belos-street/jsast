import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('detect-path-traversal rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.registerRule('detect-path-traversal')
  })

  it('should detect fs.readFile with template literal', () => {
    const code = 'fs.readFile(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('Path traversal vulnerability')
    expect(issues[0]!.message).toContain('readFile')
  })

  it('should detect fs.readFileSync with binary expression', () => {
    const code = 'fs.readFileSync("./data/" + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readFileSync')
  })

  it('should detect fs.writeFile with template literal', () => {
    const code = 'fs.writeFile(`./output/${filename}`, data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('writeFile')
  })

  it('should detect fs.writeFileSync with binary expression', () => {
    const code = 'fs.writeFileSync("./output/" + filename, data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('writeFileSync')
  })

  it('should detect fs.unlink with template literal', () => {
    const code = 'fs.unlink(`./files/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('unlink')
  })

  it('should detect fs.unlinkSync with binary expression', () => {
    const code = 'fs.unlinkSync("./files/" + userInput)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('unlinkSync')
  })

  it('should detect fs.existsSync with template literal', () => {
    const code = 'fs.existsSync(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('existsSync')
  })

  it('should detect fs.stat with template literal', () => {
    const code = 'fs.stat(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('stat')
  })

  it('should detect fs.readdir with template literal', () => {
    const code = 'fs.readdir(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readdir')
  })

  it('should detect fs.mkdir with template literal', () => {
    const code = 'fs.mkdir(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('mkdir')
  })

  it('should detect fs.rmdir with template literal', () => {
    const code = 'fs.rmdir(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('rmdir')
  })

  it('should detect require fs.readFile with template literal', () => {
    const code = "require('fs').readFile(`./data/${userInput}`)"
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain("require('fs')")
  })

  it('should detect direct readFile call with template literal', () => {
    const code = 'readFile(`./data/${userInput}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('readFile')
  })

  it('should not detect fs.readFile with static string', () => {
    const code = 'fs.readFile("./data/config.json")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect fs.readFileSync with static string', () => {
    const code = 'fs.readFileSync("./data/config.json")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other fs methods', () => {
    const code = 'fs.createReadStream("./data/config.json")'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should not detect other function calls', () => {
    const code = 'Math.random()'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(0)
  })

  it('should detect multiple unsafe path operations', () => {
    const code = 'fs.readFile(`./data/${x}`); fs.writeFileSync("./output/" + y, data)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect fs.appendFile with template literal', () => {
    const code = 'fs.appendFile(`./logs/${userInput}`, logData)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('appendFile')
  })

  it('should detect fs.appendFileSync with binary expression', () => {
    const code = 'fs.appendFileSync("./logs/" + userInput, logData)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('appendFileSync')
  })

  it('should detect fs.rename with template literal', () => {
    const code = 'fs.rename(`./old/${oldName}`, `./new/${newName}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect fs.copyFile with template literal', () => {
    const code = 'fs.copyFile(`./src/${filename}`, `./dest/${filename}`)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(2)
  })

  it('should detect fs.access with template literal', () => {
    const code = 'fs.access(`./data/${userInput}`, fs.constants.R_OK)'
    const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
    expect(issues.length).toBe(1)
    expect(issues[0]!.message).toContain('access')
  })
})
