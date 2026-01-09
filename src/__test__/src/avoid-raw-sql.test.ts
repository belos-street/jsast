import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'
import type { ReportIssue } from '../../report/type'

describe('avoid-raw-sql rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('avoid-raw-sql')
  })

  describe('Sequelize raw SQL queries', () => {
    it('should detect sequelize.query with raw SQL string', () => {
      const code = "sequelize.query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('raw SQL')
      expect(issues[0]!.message).toContain('sequelize.query')
    })

    it('should detect sequelize.query with template literal', () => {
      const code = "sequelize.query(`SELECT * FROM users WHERE id = ${userId}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('raw SQL')
    })

    it('should detect sequelize.query with string concatenation', () => {
      const code = "sequelize.query('SELECT * FROM users WHERE name = ' + name)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with INSERT statement', () => {
      const code = "sequelize.query('INSERT INTO users (name, email) VALUES (\"John\", \"john@example.com\")')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with UPDATE statement', () => {
      const code = "sequelize.query('UPDATE users SET status = \"active\"')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with DELETE statement', () => {
      const code = "sequelize.query('DELETE FROM users WHERE id = 1')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with CREATE TABLE statement', () => {
      const code = "sequelize.query('CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(255))')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with DROP TABLE statement', () => {
      const code = "sequelize.query('DROP TABLE IF EXISTS users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sequelize.query with ALTER TABLE statement', () => {
      const code = "sequelize.query('ALTER TABLE users ADD COLUMN age INT')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('TypeORM raw SQL queries', () => {
    it('should detect typeorm.query with raw SQL string', () => {
      const code = "connection.query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('raw SQL')
    })

    it('should detect typeorm.query with template literal', () => {
      const code = "connection.query(`SELECT * FROM users WHERE id = ${userId}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect typeorm.createQueryBuilder with raw SQL', () => {
      const code = "connection.createQueryBuilder().where('name = :name', { name: 'John' }).getRawMany()"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should detect typeorm.query with INSERT', () => {
      const code = "connection.query('INSERT INTO users (name) VALUES (\"John\")')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Knex.js raw SQL queries', () => {
    it('should detect knex.raw with raw SQL string', () => {
      const code = "knex.raw('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('raw SQL')
    })

    it('should detect knex.raw with template literal', () => {
      const code = "knex.raw(`SELECT * FROM users WHERE id = ${userId}`)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect knex.raw with string concatenation', () => {
      const code = "knex.raw('SELECT * FROM users WHERE name = ' + name)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect knex.raw with INSERT', () => {
      const code = "knex.raw('INSERT INTO users (name) VALUES (\"John\")')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Prisma raw SQL queries', () => {
    it('should detect prisma.$queryRaw with raw SQL string', () => {
      const code = "prisma.$queryRaw`SELECT * FROM users`"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('raw SQL')
    })

    it('should detect prisma.$queryRaw with dynamic content', () => {
      const code = "prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect prisma.$executeRaw with raw SQL string', () => {
      const code = "prisma.$executeRaw`INSERT INTO users (name) VALUES ('John')`"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Direct database library raw queries', () => {
    it('should detect mysql.query with raw SQL', () => {
      const code = "mysql.query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('raw SQL')
    })

    it('should detect pg.query with raw SQL', () => {
      const code = "pg.query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect sqlite3.run with raw SQL', () => {
      const code = "sqlite3.run('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })

  describe('Safe ORM queries (should not trigger)', () => {
    it('should not detect Sequelize findAll method', () => {
      const code = "User.findAll({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Sequelize findOne method', () => {
      const code = "User.findOne({ where: { email: userEmail } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Sequelize create method', () => {
      const code = "User.create({ name: 'John', email: 'john@example.com' })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Sequelize update method', () => {
      const code = "User.update({ status: 'active' }, { where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Sequelize destroy method', () => {
      const code = "User.destroy({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect TypeORM find method', () => {
      const code = "userRepository.find({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect TypeORM findOne method', () => {
      const code = "userRepository.findOne({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect TypeORM save method', () => {
      const code = "userRepository.save(user)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect TypeORM remove method', () => {
      const code = "userRepository.remove(user)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Prisma findMany method', () => {
      const code = "prisma.user.findMany({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Prisma findUnique method', () => {
      const code = "prisma.user.findUnique({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Prisma create method', () => {
      const code = "prisma.user.create({ data: { name: 'John' } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Prisma update method', () => {
      const code = "prisma.user.update({ where: { id: userId }, data: { status: 'active' } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Prisma delete method', () => {
      const code = "prisma.user.delete({ where: { id: userId } })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Knex query builder', () => {
      const code = "knex('users').select('*').where('id', userId)"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Knex insert', () => {
      const code = "knex('users').insert({ name: 'John', email: 'john@example.com' })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Knex update', () => {
      const code = "knex('users').where('id', userId).update({ status: 'active' })"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Knex delete', () => {
      const code = "knex('users').where('id', userId).del()"
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

  describe('Multiple raw SQL queries', () => {
    it('should detect multiple raw SQL queries', () => {
      const code = "sequelize.query('SELECT * FROM users'); sequelize.query('SELECT * FROM products')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should detect mix of different ORM raw queries', () => {
      const code = "sequelize.query('SELECT * FROM users'); knex.raw('SELECT * FROM products')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })
  })

  describe('Edge cases', () => {
    it('should handle empty string', () => {
      const code = "sequelize.query('')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should handle non-SQL string', () => {
      const code = "sequelize.query('Hello World')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should detect require sequelize pattern', () => {
      const code = "require('sequelize').query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require knex pattern', () => {
      const code = "require('knex').raw('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require mysql pattern', () => {
      const code = "require('mysql').query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require pg pattern', () => {
      const code = "require('pg').query('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should detect require sqlite3 pattern', () => {
      const code = "require('sqlite3').run('SELECT * FROM users')"
      const issues: ReportIssue[] = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })
  })
})
