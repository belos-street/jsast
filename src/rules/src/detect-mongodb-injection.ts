import type { Expression, ObjectExpression } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * MongoDB注入检测规则
 *
 * 设计思路：
 * 1. 检测$where操作符中的动态内容（字符串拼接或模板字符串）
 * 2. 检测直接使用用户输入作为查询条件，未使用MongoDB操作符（如$eq）
 * 3. 支持多种MongoDB查询方法：find, findOne, update, deleteOne, deleteMany
 * 4. 支持Mongoose模型的查询方法
 * 5. 忽略安全的查询模式：使用操作符、ObjectId构造、静态字符串
 *
 * 检测范围：
 * - $where操作符：`db.collection.find({ $where: 'this.name == ' + userInput })`
 * - 直接用户输入：`db.collection.find({ name: userInput })`
 * - Mongoose模型查询：`User.find({ email: userEmail })`
 *
 * 安全模式（不检测）：
 * - 使用操作符：`db.collection.find({ name: { $eq: userInput } })`
 * - ObjectId构造：`db.collection.find({ _id: new ObjectId(userId) })`
 * - 静态字符串：`db.collection.find({ name: 'John' })`
 * - Mongoose findById：`User.findById(userId)`
 */
export const detectMongoDbInjectionRule: Rule = {
  name: 'detect-mongodb-injection',
  description: 'Detects MongoDB injection vulnerabilities',
  severity: 'error',
  category: 'sql-injection',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      const mongoDbMethods = ['find', 'findOne', 'update', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'remove']
      const mongooseModels = ['User', 'Product', 'Order', 'Account', 'Session', 'Document']

      const hasDynamicContent = (arg: Expression): boolean => {
        if (arg.type === 'TemplateLiteral') {
          return arg.expressions.length > 0
        }
        if (arg.type === 'BinaryExpression') {
          return true
        }
        return false
      }

      const checkWhereOperator = (queryObj: ObjectExpression) => {
        for (const prop of queryObj.properties) {
          if (prop.type === 'ObjectProperty' && prop.key.type === 'Identifier' && prop.key.name === '$where') {
            const value = prop.value
            if (value.type === 'StringLiteral' || value.type === 'TemplateLiteral' || value.type === 'BinaryExpression') {
              if (hasDynamicContent(value)) {
                return true
              }
            }
          }
        }
        return false
      }

      const checkDirectUserInput = (queryObj: ObjectExpression): number => {
        let count = 0
        for (const prop of queryObj.properties) {
          if (prop.type === 'ObjectProperty') {
            const key = prop.key
            const value = prop.value

            if (key.type === 'Identifier') {
              const keyName = key.name

              if (keyName === '$where') {
                continue
              }

              if (keyName.startsWith('$')) {
                if (keyName === '$or' || keyName === '$and') {
                  if (value.type === 'ArrayExpression') {
                    for (const element of value.elements) {
                      if (element && element.type === 'ObjectExpression') {
                        count += checkDirectUserInput(element)
                      }
                    }
                  }
                }
                continue
              }

              if (value.type === 'Identifier') {
                count++
              }

              if (value.type === 'ObjectExpression') {
                const hasOperator = (value as ObjectExpression).properties.some(
                  (p) => p.type === 'ObjectProperty' && p.key.type === 'Identifier' && p.key.name.startsWith('$')
                )
                if (!hasOperator) {
                  count += checkDirectUserInput(value as ObjectExpression)
                }
              }
            }
          }
        }
        return count
      }

      const checkMongoDbInjection = (methodName: string, modelName?: string) => {
        const firstArg = node.arguments[0] as Expression
        if (firstArg && firstArg.type === 'ObjectExpression') {
          const queryObj = firstArg

          if (checkWhereOperator(queryObj)) {
            const modelPrefix = modelName ? `${modelName}.` : ''
            issues.push({
              message: `MongoDB injection vulnerability: ${modelPrefix}${methodName} uses $where operator with dynamic content, vulnerable to MongoDB injection`,
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }

          const userInputCount = checkDirectUserInput(queryObj)
          for (let i = 0; i < userInputCount; i++) {
            const modelPrefix = modelName ? `${modelName}.` : ''
            issues.push({
              message: `MongoDB injection vulnerability: ${modelPrefix}${methodName} uses direct user input without MongoDB operators, consider using $eq operator`,
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }
        }
      }

      if (callee.type === 'MemberExpression') {
        const property = callee.property

        if (property.type === 'Identifier' && mongoDbMethods.includes(property.name)) {
          const object = callee.object

          if (object.type === 'Identifier') {
            const objectName = object.name

            if (mongooseModels.includes(objectName)) {
              checkMongoDbInjection(property.name, objectName)
            } else if (objectName === 'collection' || objectName === 'db') {
              checkMongoDbInjection(property.name, objectName)
            }
          } else if (object.type === 'MemberExpression') {
            const nestedObject = object.object
            const nestedProperty = object.property

            if (nestedObject.type === 'Identifier' && nestedProperty.type === 'Identifier') {
              if (nestedObject.name === 'db' && nestedProperty.name === 'collection') {
                checkMongoDbInjection(property.name, 'db.collection')
              }
            }
          }
        }
      }
    }

    return issues
  }
}
