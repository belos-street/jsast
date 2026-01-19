import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 使用安全随机数生成器规则
 *
 * 设计思路：
 * 1. 检测 Math.random() 的调用，因为 Math.random() 不是密码学安全的随机数生成器
 * 2. 检测各种使用场景：直接调用、函数调用、表达式、数组、对象等
 * 3. 不检测 crypto 模块的安全随机数方法（如 crypto.randomBytes、crypto.randomInt、crypto.randomUUID）
 * 4. 不检测 Math 模块的其他方法和属性（如 Math.floor、Math.PI、Math.E）
 *
 * 安全模式（不检测）：
 * - crypto.randomBytes(16).toString("hex"): Node.js 安全随机数
 * - crypto.randomInt(1, 100): Node.js 安全随机整数
 * - crypto.randomUUID(): Node.js UUID 生成
 * - Math.floor(10.5): Math 模块其他方法
 * - Math.PI: Math 模块属性
 * - Math.E: Math 模块属性
 * - Math.sin(1): Math 模块三角函数
 * - Math.cos(1): Math 模块三角函数
 * - Math.sqrt(4): Math 模块数学函数
 * - Math.abs(-1): Math 模块数学函数
 */
export const useSecureRandomRule: Rule = {
  name: 'use-secure-random',
  description: 'Use secure random number generation instead of Math.random()',
  severity: 'warning',
  category: 'insecure-randomness',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'Math' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'random'
      ) {
        issues.push({
          message:
            'Insecure random number generation: Math.random() is not cryptographically secure. Use crypto.randomBytes(), crypto.randomInt(), or crypto.randomUUID() for security-sensitive operations',
          line: node.loc.start.line,
          column: node.loc.start.column
        })
      }
    }

    return issues
  }
}
