import { describe, it, expect, beforeEach } from 'bun:test'
import { RuleTestHelper } from '../rule-test-helper'

describe('detect-mongodb-injection rule', () => {
  let helper: RuleTestHelper

  beforeEach(() => {
    helper = new RuleTestHelper()
    helper.clearRules()
    helper.registerRule('detect-mongodb-injection')
  })

  describe('$where operator injection', () => {
    it('should detect $where with string concatenation', () => {
      const code = "db.collection.find({ $where: 'this.name == \\'' + userInput + '\\'' })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
      expect(issues[0]!.message).toContain('injection')
    })

    it('should detect $where with template literal', () => {
      const code = "db.collection.find({ $where: `this.name == '${userInput}'` })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
    })

    it('should detect $where with function call', () => {
      const code = "db.collection.find({ $where: 'function() { return this.name == ' + userInput + ' }' })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
    })

    it('should detect $where in findOne', () => {
      const code = "db.collection.findOne({ $where: 'this.age > ' + ageInput })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
    })

    it('should detect $where in update', () => {
      const code = "db.collection.update({ $where: 'this.name == ' + nameInput }, { $set: { active: true } })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
    })

    it('should detect $where in delete', () => {
      const code = "db.collection.deleteMany({ $where: 'this.status == ' + statusInput })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
    })
  })

  describe('Direct user input without operators', () => {
    it('should detect direct user input in find', () => {
      const code = 'db.collection.find({ name: userInput })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
      expect(issues[0]!.message).toContain('$eq')
    })

    it('should detect direct user input in findOne', () => {
      const code = 'db.collection.findOne({ email: userEmail })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
    })

    it('should detect direct user input in update', () => {
      const code = 'db.collection.update({ id: userId }, { $set: { name: newName } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
    })

    it('should detect direct user input in delete', () => {
      const code = 'db.collection.deleteOne({ _id: deleteId })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
    })

    it('should detect direct user input with multiple fields', () => {
      const code = 'db.collection.find({ name: userName, age: userAge })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })
  })

  describe('Mongoose model queries', () => {
    it('should detect $where in Mongoose find', () => {
      const code = "User.find({ $where: 'this.name == \\'' + userInput + '\\'' })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('$where')
    })

    it('should detect direct user input in Mongoose find', () => {
      const code = 'Product.find({ category: userCategory })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
    })

    it('should detect direct user input in Mongoose findOne', () => {
      const code = 'Order.findOne({ orderId: userOrderId })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
    })

    it('should detect direct user input in Mongoose update', () => {
      const code = 'User.update({ email: userEmail }, { $set: { verified: true } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
      expect(issues[0]!.message).toContain('user input')
    })
  })

  describe('Safe queries (should not trigger)', () => {
    it('should not detect static string in find', () => {
      const code = "db.collection.find({ name: 'John' })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect $eq operator', () => {
      const code = 'db.collection.find({ name: { $eq: userInput } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect $in operator', () => {
      const code = 'db.collection.find({ id: { $in: userIds } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect $gt operator', () => {
      const code = 'db.collection.find({ age: { $gt: minAge } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect $lt operator', () => {
      const code = 'db.collection.find({ price: { $lt: maxPrice } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect $regex operator', () => {
      const code = 'db.collection.find({ name: { $regex: namePattern } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect ObjectId constructor', () => {
      const code = 'db.collection.find({ _id: new ObjectId(userId) })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Mongoose findById', () => {
      const code = 'User.findById(userId)'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect Mongoose findOne with ObjectId', () => {
      const code = 'User.findOne({ _id: new ObjectId(userId) })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should not detect static $where without user input', () => {
      const code = "db.collection.find({ $where: 'this.age > 18' })"
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('Edge cases', () => {
    it('should handle empty object', () => {
      const code = 'db.collection.find({})'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should handle nested objects', () => {
      const code = 'db.collection.find({ address: { city: userCity } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(1)
    })

    it('should handle array in query', () => {
      const code = 'db.collection.find({ tags: { $all: userTags } })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should handle $or with user input', () => {
      const code = 'db.collection.find({ $or: [{ name: userName }, { email: userEmail }] })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should handle $and with user input', () => {
      const code = 'db.collection.find({ $and: [{ age: userAge }, { status: userStatus }] })'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should handle non-database function calls', () => {
      const code = 'console.log(userInput)'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })

    it('should handle Math.random()', () => {
      const code = 'const x = Math.random()'
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(0)
    })
  })

  describe('Multiple MongoDB injection patterns', () => {
    it('should detect multiple $where operators', () => {
      const code = `
        db.collection.find({ $where: 'this.name == \\'' + userInput + '\\'' })
        db.collection.findOne({ $where: 'this.age > ' + ageInput })
      `
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })

    it('should detect mix of $where and direct input', () => {
      const code = `
        db.collection.find({ $where: 'this.name == \\'' + userInput + '\\'' })
        db.collection.find({ name: userName })
      `
      const issues = helper.getAnalyzer().analyzeFile('test.js', code)
      expect(issues.length).toBe(2)
    })
  })
})
