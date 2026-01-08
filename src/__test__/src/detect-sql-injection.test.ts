import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('detect-sql-injection rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('detect-sql-injection')
  })

  describe('MySQL query with template literal', () => {
    it('should detect mysql.query with template literal', () => {
      const code = "mysql.query(`SELECT * FROM users WHERE id = ${userInput}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('SQL injection')
      expect(issues[0]!.message).toContain('mysql.query')
    })

    it('should detect mysql2.query with template literal', () => {
      const code = "mysql2.query(`SELECT * FROM users WHERE name = '${name}'`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('SQL injection')
    })

    it('should detect connection.query with template literal', () => {
      const code = "connection.query(`SELECT * FROM products WHERE price > ${price}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('MySQL query with binary expression', () => {
    it('should detect mysql.query with string concatenation', () => {
      const code = "mysql.query('SELECT * FROM users WHERE id = ' + userInput)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('SQL injection')
    })

    it('should detect mysql.query with multiple concatenations', () => {
      const code = "mysql.query('SELECT * FROM users WHERE name = ' + name + ' AND age > ' + age)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('PostgreSQL query', () => {
    it('should detect pg.query with template literal', () => {
      const code = "client.query(`SELECT * FROM users WHERE id = ${userId}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('SQL injection')
    })

    it('should detect pg.Client.query with template literal', () => {
      const code = "new pg.Client().query(`INSERT INTO users (name) VALUES ('${name}')`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect pg.Pool.query with template literal', () => {
      const code = "pool.query(`DELETE FROM users WHERE id = ${id}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('SQLite query', () => {
    it('should detect sqlite3.run with template literal', () => {
      const code = "db.run(`UPDATE users SET name = '${name}' WHERE id = ${id}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sqlite3.exec with template literal', () => {
      const code = "db.exec(`SELECT * FROM users WHERE email = '${email}'`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sqlite3.all with string concatenation', () => {
      const code = "db.all('SELECT * FROM users WHERE age > ' + age)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Sequelize query', () => {
    it('should detect sequelize.query with template literal', () => {
      const code = "sequelize.query(`SELECT * FROM users WHERE id = ${userId}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with string concatenation', () => {
      const code = "sequelize.query('SELECT * FROM users WHERE name = ' + name)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Mongoose query', () => {
    it('should detect mongoose.find with template literal', () => {
      const code = "User.find({ name: { $regex: new RegExp('^' + userInput) } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should detect mongoose.where with template literal', () => {
      const code = "User.where(`name = ${name}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Direct database function calls', () => {
    it('should detect direct query call with template literal', () => {
      const code = "query(`SELECT * FROM users WHERE id = ${id}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect direct execute call with template literal', () => {
      const code = "execute(`INSERT INTO users (name) VALUES ('${name}')`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect direct exec call with template literal', () => {
      const code = "exec(`UPDATE users SET status = '${status}'`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Safe queries (should not trigger)', () => {
    it('should not detect query with static string', () => {
      const code = "mysql.query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect query with parameterized query', () => {
      const code = "mysql.query('SELECT * FROM users WHERE id = ?', [userId])"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect query with named parameters', () => {
      const code = "pg.query('SELECT * FROM users WHERE id = $1', [userId])"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect other function calls', () => {
      const code = "console.log('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Math.random()', () => {
      const code = "Math.random()"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('Multiple SQL injections', () => {
    it('should detect multiple unsafe queries', () => {
      const code = "mysql.query(`SELECT * FROM users WHERE id = ${id}`); pg.query(`SELECT * FROM products WHERE name = '${name}'`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should detect mix of template literal and concatenation', () => {
      const code = "mysql.query(`SELECT * FROM users WHERE id = ${id}`); mysql.query('SELECT * FROM users WHERE name = ' + name)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })
  })

  describe('Edge cases', () => {
    it('should handle empty template literal', () => {
      const code = "mysql.query('')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should handle template literal with only static content', () => {
      const code = "mysql.query(`SELECT * FROM users`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should detect require mysql pattern', () => {
      const code = "require('mysql').query(`SELECT * FROM users WHERE id = ${id}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require mysql2 pattern', () => {
      const code = "require('mysql2').query(`SELECT * FROM users WHERE id = ${id}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require pg pattern', () => {
      const code = "require('pg').Client().query(`SELECT * FROM users WHERE id = ${id}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require sqlite3 pattern', () => {
      const code = "require('sqlite3').Database().run(`UPDATE users SET name = '${name}'`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })
})
