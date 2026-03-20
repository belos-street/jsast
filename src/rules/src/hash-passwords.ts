import type { Node } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测明文密码存储规则
 *
 * 设计思路：
 * 1. 检测数据库操作中直接存储明文密码
 * 2. 检测对象属性中直接赋值明文密码
 * 3. 识别常见的密码相关字段名
 * 4. 忽略使用密码哈希函数的情况
 *
 * 检测范围：
 * - 数据库插入/更新：INSERT/UPDATE 语句中的 password 字段
 * - 对象字面量：{ password: 'plaintext' }
 * - 变量赋值：user.password = 'plaintext'
 * - Mongoose/Sequelize 模型中的密码字段
 *
 * 安全模式（不检测）：
 * - 使用哈希函数：bcrypt.hash(), crypto.createHash()
 * - 密码比较：bcrypt.compare(), user.comparePassword()
 * - 密码验证：检查密码长度、复杂度
 * - 已知的安全密码处理库
 */

const PASSWORD_FIELDS = [
  'password',
  'passwd',
  'pwd',
  'pass',
  'userPassword',
  'user_password',
  'userPass',
  'user_pass',
  'adminPassword',
  'admin_password',
  'adminPass',
  'admin_pass',
  'loginPassword',
  'login_password',
  'loginPass',
  'login_pass'
]

const HASHING_FUNCTIONS = [
  'hash',
  'createHash',
  'pbkdf2',
  'scrypt',
  'compare',
  'compareSync',
  'verify',
  'verifySync',
  'encrypt',
  'encryptSync'
]

const HASHING_LIBRARIES = ['bcrypt', 'bcryptjs', 'argon2', 'scrypt', 'crypto']

function isPasswordField(name: string): boolean {
  return PASSWORD_FIELDS.includes(name)
}

function isHashingFunction(node: Node): boolean {
  if (node.type === 'Identifier' && HASHING_FUNCTIONS.includes(node.name)) {
    return true
  }
  if (node.type === 'MemberExpression') {
    const property = node.property
    if (property.type === 'Identifier' && HASHING_FUNCTIONS.includes(property.name)) {
      const object = node.object
      if (object.type === 'Identifier' && HASHING_LIBRARIES.includes(object.name)) {
        return true
      }
    }
  }
  if (node.type === 'CallExpression') {
    return isHashingFunction(node.callee)
  }
  return false
}

function isStringLiteral(node: Node): boolean {
  return node.type === 'StringLiteral' || node.type === 'TemplateLiteral'
}

function isPlaintextPassword(node: Node): boolean {
  if (!node) return false
  if (isStringLiteral(node)) return true
  if (node.type === 'Identifier') return true
  if (node.type === 'BinaryExpression') return true
  if (node.type === 'TemplateLiteral' && node.expressions && node.expressions.length > 0) {
    return !node.expressions.some((expr: Node) => isHashingFunction(expr))
  }
  return false
}

export const hashPasswordsRule: Rule = {
  name: 'hash-passwords',
  description: 'Detect plaintext password storage',
  severity: 'error',
  category: 'insecure-authentication',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'AssignmentExpression' && node.loc) {
      const left = node.left
      const right = node.right

      if (left.type === 'MemberExpression') {
        const property = left.property
        if (property.type === 'Identifier' && isPasswordField(property.name)) {
          if (isPlaintextPassword(right) && !isHashingFunction(right)) {
            issues.push({
              message: `Plaintext password storage: The '${property.name}' field is being assigned without hashing. Use password hashing functions like bcrypt, argon2, or crypto.pbkdf2 to securely hash passwords before storage`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'MemberExpression') {
        const property = callee.property

        if (property.type === 'Identifier' && ['create', 'insert', 'update', 'save'].includes(property.name)) {
          const args = node.arguments

          if (args.length > 0 && args[0]) {
            const firstArg = args[0]

            if (firstArg.type === 'ObjectExpression') {
              for (const prop of firstArg.properties) {
                if (prop.type === 'ObjectProperty') {
                  const keyName = prop.key.type === 'Identifier' ? prop.key.name : ''
                  const value = prop.value

                  if (isPasswordField(keyName) && isPlaintextPassword(value)) {
                    if (!isHashingFunction(value)) {
                      issues.push({
                        message: `Plaintext password storage: The '${keyName}' field is being stored in database without hashing. Use password hashing functions like bcrypt, argon2, or crypto.pbkdf2 to securely hash passwords before storage`,
                        line: prop.loc!.start.line,
                        column: prop.loc!.start.column
                      })
                    }
                  }
                }
              }
            }
          }
        }

        if (property.type === 'Identifier' && property.name === 'set') {
          const args = node.arguments

          if (args.length >= 2 && args[0] && args[1]) {
            const firstArg = args[0]
            const secondArg = args[1]

            if (firstArg.type === 'StringLiteral' && isPasswordField(firstArg.value)) {
              if (isPlaintextPassword(secondArg) && !isHashingFunction(secondArg)) {
                issues.push({
                  message: `Plaintext password storage: Setting '${firstArg.value}' without hashing. Use password hashing functions like bcrypt, argon2, or crypto.pbkdf2 to securely hash passwords before storage`,
                  line: node.loc.start.line,
                  column: node.loc.start.column
                })
              }
            }
          }
        }
      }

      if (callee.type === 'Identifier' && ['insert', 'update', 'create'].includes(callee.name)) {
        const args = node.arguments

        if (args.length > 0 && args[0]) {
          const firstArg = args[0]

          if (firstArg.type === 'ObjectExpression') {
            for (const prop of firstArg.properties) {
              if (prop.type === 'ObjectProperty') {
                const keyName = prop.key.type === 'Identifier' ? prop.key.name : ''
                const value = prop.value

                if (isPasswordField(keyName) && isPlaintextPassword(value)) {
                  if (!isHashingFunction(value)) {
                    issues.push({
                      message: `Plaintext password storage: The '${keyName}' field is being stored in database without hashing. Use password hashing functions like bcrypt, argon2, or crypto.pbkdf2 to securely hash passwords before storage`,
                      line: prop.loc!.start.line,
                      column: prop.loc!.start.column
                    })
                  }
                }
              }
            }
          }
        }
      }
    }

    return issues
  }
}
