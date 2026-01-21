import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 避免使用弱加密算法规则
 *
 * 设计思路：
 * 1. 检测 crypto.createHash 调用，检查使用的哈希算法
 * 2. 识别弱加密算法：md5、sha1、md4、ripemd160 等
 * 3. 不检测强加密算法：sha256、sha384、sha512、sha3 等
 * 4. 只检测字符串字面量参数，不检测变量或表达式
 *
 * 检测范围：
 * - crypto.createHash('md5'): MD5 哈希算法
 * - crypto.createHash('sha1'): SHA1 哈希算法
 * - crypto.createHash('md4'): MD4 哈希算法
 * - crypto.createHash('ripemd160'): RIPEMD160 哈希算法
 * - crypto.createHash('MD5'): 大写 MD5
 * - crypto.createHash('SHA1'): 大写 SHA1
 * - crypto.createHash('Md5'): 混合大小写 MD5
 * - crypto.createHash('Sha1'): 混合大小写 SHA1
 *
 * 安全模式（不检测）：
 * - crypto.createHash('sha256'): SHA256 哈希算法
 * - crypto.createHash('sha384'): SHA384 哈希算法
 * - crypto.createHash('sha512'): SHA512 哈希算法
 * - crypto.createHash('sha3'): SHA3 哈希算法
 * - crypto.randomBytes(16): 随机字节生成
 * - crypto.createCipher('aes-256-cbc', key): 对称加密
 * - crypto.createDecipher('aes-256-cbc', key): 对称解密
 * - crypto.createSign('sha256'): 数字签名
 * - crypto.createVerify('sha256'): 签名验证
 * - crypto.createHash(variable): 变量参数（无法静态分析）
 * - crypto.createHash(`md5`): 模板字符串参数
 * - crypto.createHash('md' + '5'): 二元表达式参数
 * - crypto.createHash(getAlgorithm()): 函数调用参数
 */
export const avoidWeakCryptoRule: Rule = {
  name: 'avoid-weak-crypto',
  description: 'Avoid using weak cryptographic algorithms',
  severity: 'warning',
  category: 'insecure-randomness',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'crypto' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'createHash'
      ) {
        const firstArg = node.arguments[0]

        if (firstArg && firstArg.type === 'StringLiteral') {
          const algorithm = firstArg.value.toLowerCase()

          const weakAlgorithms = ['md5', 'sha1', 'md4', 'ripemd160']

          if (weakAlgorithms.includes(algorithm)) {
            issues.push({
              message: `Weak cryptographic algorithm: ${algorithm} is not secure. Use sha256, sha384, or sha512 instead for better security`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    return issues
  }
}
