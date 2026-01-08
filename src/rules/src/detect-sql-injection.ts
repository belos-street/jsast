import type { Expression } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * SQL注入检测规则
 */
export const detectSqlInjectionRule: Rule = {
  name: 'detect-sql-injection',
  description: 'Detects SQL injection vulnerabilities',
  severity: 'error',
  category: 'sql-injection',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      const sqlMethods = ['query', 'execute', 'exec', 'run', 'all', 'where']
      const mysqlLibraries = ['mysql', 'mysql2']
      const pgLibraries = ['pg']
      const sqliteLibraries = ['sqlite3']

      const hasDynamicContent = (arg: Expression): boolean => {
        if (arg.type === 'TemplateLiteral') {
          return arg.expressions.length > 0
        }
        if (arg.type === 'BinaryExpression') {
          return true
        }
        return false
      }

      const checkSqlInjection = (methodName: string, libraryName?: string) => {
        const firstArg = node.arguments[0] as Expression
        if (firstArg && hasDynamicContent(firstArg)) {
          const libPrefix = libraryName ? `${libraryName}.` : ''
          issues.push({
            message: `SQL injection vulnerability: ${libPrefix}${methodName} uses dynamically concatenated SQL string, vulnerable to SQL injection`,
            line: node.loc!.start.line,
            column: node.loc!.start.column
          })
        }
      }

      if (callee.type === 'MemberExpression') {
        const property = callee.property

        if (property.type === 'Identifier' && sqlMethods.includes(property.name)) {
          const object = callee.object

          if (object.type === 'Identifier') {
            const objectName = object.name

            if (mysqlLibraries.includes(objectName)) {
              checkSqlInjection(property.name, objectName)
            } else if (pgLibraries.includes(objectName)) {
              checkSqlInjection(property.name, objectName)
            } else if (sqliteLibraries.includes(objectName)) {
              checkSqlInjection(property.name, objectName)
            } else if (objectName === 'sequelize') {
              checkSqlInjection(property.name, objectName)
            } else if (objectName === 'connection' || objectName === 'pool' || objectName === 'client' || objectName === 'db') {
              checkSqlInjection(property.name, objectName)
            } else if (['User', 'Product', 'Order'].includes(objectName)) {
              if (property.name === 'where') {
                checkSqlInjection(property.name, objectName)
              }
            }
          }

          if (object.type === 'NewExpression' && object.callee.type === 'Identifier') {
            const className = object.callee.name

            if (className === 'Client' && property.name === 'query') {
              checkSqlInjection(property.name, 'pg.Client')
            } else if (className === 'Database' && ['run', 'exec', 'all'].includes(property.name)) {
              checkSqlInjection(property.name, 'sqlite3.Database')
            }
          }

          if (object.type === 'NewExpression' && object.callee.type === 'MemberExpression') {
            const memberCallee = object.callee
            if (memberCallee.property.type === 'Identifier' && memberCallee.property.name === 'Client') {
              if (memberCallee.object.type === 'Identifier' && pgLibraries.includes(memberCallee.object.name)) {
                checkSqlInjection(property.name, 'pg.Client')
              }
            }
          }

          if (object.type === 'CallExpression' && object.callee.type === 'Identifier' && object.callee.name === 'require') {
            const requireArg = object.arguments[0]
            if (requireArg && requireArg.type === 'StringLiteral') {
              const libName = requireArg.value

              if (mysqlLibraries.includes(libName) && property.name === 'query') {
                checkSqlInjection(property.name, libName)
              } else if (pgLibraries.includes(libName) && property.name === 'query') {
                checkSqlInjection(property.name, libName)
              } else if (sqliteLibraries.includes(libName) && sqlMethods.includes(property.name)) {
                checkSqlInjection(property.name, libName)
              }
            }
          }

          if (object.type === 'MemberExpression' && object.property.type === 'Identifier') {
            const outerProperty = object.property

            if (outerProperty.name === 'Client' && property.name === 'query') {
              const innerObject = object.object
              if (innerObject.type === 'Identifier' && pgLibraries.includes(innerObject.name)) {
                checkSqlInjection(property.name, 'pg.Client')
              }
              if (
                innerObject.type === 'CallExpression' &&
                innerObject.callee.type === 'Identifier' &&
                innerObject.callee.name === 'require'
              ) {
                const requireArg = innerObject.arguments[0]
                if (requireArg && requireArg.type === 'StringLiteral' && requireArg.value === 'pg') {
                  checkSqlInjection(property.name, 'pg.Client')
                }
              }
            }

            if (outerProperty.name === 'Database' && ['run', 'exec', 'all'].includes(property.name)) {
              const innerObject = object.object
              if (innerObject.type === 'Identifier' && sqliteLibraries.includes(innerObject.name)) {
                checkSqlInjection(property.name, 'sqlite3.Database')
              }
              if (
                innerObject.type === 'CallExpression' &&
                innerObject.callee.type === 'Identifier' &&
                innerObject.callee.name === 'require'
              ) {
                const requireArg = innerObject.arguments[0]
                if (requireArg && requireArg.type === 'StringLiteral' && requireArg.value === 'sqlite3') {
                  checkSqlInjection(property.name, 'sqlite3.Database')
                }
              }
            }
          }

          if (object.type === 'CallExpression' && object.callee.type === 'MemberExpression') {
            const innerCallee = object.callee
            if (innerCallee.property.type === 'Identifier') {
              const innerProperty = innerCallee.property

              if (innerProperty.name === 'Client' && property.name === 'query') {
                const innerObject = innerCallee.object
                if (
                  innerObject.type === 'CallExpression' &&
                  innerObject.callee.type === 'Identifier' &&
                  innerObject.callee.name === 'require'
                ) {
                  const requireArg = innerObject.arguments[0]
                  if (requireArg && requireArg.type === 'StringLiteral' && requireArg.value === 'pg') {
                    checkSqlInjection(property.name, 'pg.Client')
                  }
                }
              }

              if (innerProperty.name === 'Database' && ['run', 'exec', 'all'].includes(property.name)) {
                const innerObject = innerCallee.object
                if (
                  innerObject.type === 'CallExpression' &&
                  innerObject.callee.type === 'Identifier' &&
                  innerObject.callee.name === 'require'
                ) {
                  const requireArg = innerObject.arguments[0]
                  if (requireArg && requireArg.type === 'StringLiteral' && requireArg.value === 'sqlite3') {
                    checkSqlInjection(property.name, 'sqlite3.Database')
                  }
                }
              }
            }
          }
        }
      }

      if (callee.type === 'Identifier' && ['query', 'execute', 'exec'].includes(callee.name)) {
        checkSqlInjection(callee.name)
      }
    }

    return issues
  }
}
