import type { Expression } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 避免使用原始SQL字符串规则
 *
 * 设计思路：
 * 1. 检测使用ORM时直接执行原始SQL字符串的情况
 * 2. 支持多种ORM：Sequelize、TypeORM、Knex、Prisma
 * 3. 识别SQL关键字：SELECT、INSERT、UPDATE、DELETE、CREATE、DROP、ALTER
 * 4. 忽略ORM提供的查询构建器方法
 *
 * 检测范围：
 * - Sequelize.query(): `sequelize.query('SELECT * FROM users')`
 * - TypeORM query(): `connection.query('SELECT * FROM users')`
 * - Knex.raw(): `knex.raw('SELECT * FROM users')`
 * - Prisma $queryRaw: `prisma.$queryRaw\`SELECT * FROM users\``
 * - Prisma $executeRaw: `prisma.$executeRaw\`INSERT INTO users...\``
 * - 直接数据库库: `mysql.query('SELECT * FROM users')`
 *
 * 安全模式（不检测）：
 * - Sequelize查询构建器：`User.findAll({ where: { id: userId } })`
 * - TypeORM查询构建器：`userRepository.find({ where: { id: userId } })`
 * - Prisma查询构建器：`prisma.user.findMany({ where: { id: userId } })`
 * - Knex查询构建器：`knex('users').select('*').where('id', userId)`
 */
export const avoidRawSqlRule: Rule = {
  name: 'avoid-raw-sql',
  description: 'Avoid using raw SQL strings, use ORM query builders instead',
  severity: 'warning',
  category: 'sql-injection',
  check(node) {
    const issues: RuleIssue[] = []

    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'TRUNCATE']

    const containsSqlKeyword = (arg: Expression): boolean => {
      if (arg.type === 'StringLiteral') {
        const upperValue = arg.value.toUpperCase()
        return sqlKeywords.some((keyword) => upperValue.includes(keyword))
      }
      if (arg.type === 'TemplateLiteral') {
        const quasiValue = arg.quasis
          .map((q) => q.value.cooked)
          .join('')
          .toUpperCase()
        return sqlKeywords.some((keyword) => quasiValue.includes(keyword))
      }
      if (arg.type === 'BinaryExpression') {
        return true
      }
      return false
    }

    if (node.type === 'TaggedTemplateExpression' && node.loc) {
      const tag = node.tag

      if (tag.type === 'MemberExpression' && tag.property.type === 'Identifier') {
        const propertyName = tag.property.name
        const object = tag.object

        if (object.type === 'Identifier' && object.name === 'prisma') {
          if (propertyName === '$queryRaw' || propertyName === '$executeRaw') {
            const templateLiteral = node.quasi
            if (templateLiteral && containsSqlKeyword(templateLiteral)) {
              issues.push({
                message: `Avoid using raw SQL: prisma.${propertyName} uses raw SQL string, consider using ORM query builders instead`,
                line: node.loc!.start.line,
                column: node.loc!.start.column
              })
            }
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      const checkRawSql = (methodName: string, libraryName?: string) => {
        const firstArg = node.arguments[0] as Expression
        if (firstArg && containsSqlKeyword(firstArg)) {
          const libPrefix = libraryName ? `${libraryName}.` : ''
          issues.push({
            message: `Avoid using raw SQL: ${libPrefix}${methodName} uses raw SQL string, consider using ORM query builders instead`,
            line: node.loc!.start.line,
            column: node.loc!.start.column
          })
        }
      }

      if (callee.type === 'MemberExpression') {
        const property = callee.property

        if (
          property.type === 'Identifier' &&
          (property.name === 'query' ||
            property.name === 'run' ||
            property.name === 'execute' ||
            property.name === 'exec' ||
            property.name === 'all')
        ) {
          const object = callee.object

          if (object.type === 'Identifier') {
            const objectName = object.name

            if (objectName === 'sequelize') {
              checkRawSql('query', 'sequelize')
            } else if (objectName === 'connection' || objectName === 'manager' || objectName === 'entityManager') {
              checkRawSql('query', objectName)
            } else if (['mysql', 'mysql2', 'pg', 'sqlite3'].includes(objectName)) {
              checkRawSql(property.name, objectName)
            }
          }

          if (object.type === 'NewExpression' && object.callee.type === 'Identifier') {
            const className = object.callee.name
            if (className === 'Client' && property.name === 'query') {
              checkRawSql('query', 'pg.Client')
            }
          }

          if (object.type === 'CallExpression' && object.callee.type === 'Identifier' && object.callee.name === 'require') {
            const requireArg = object.arguments[0]
            if (requireArg && requireArg.type === 'StringLiteral') {
              const libName = requireArg.value
              if (['sequelize', 'mysql', 'mysql2', 'pg', 'sqlite3'].includes(libName)) {
                checkRawSql(property.name, libName)
              }
            }
          }
        }

        if (property.type === 'Identifier' && property.name === 'raw') {
          const object = callee.object

          if (object.type === 'Identifier' && object.name === 'knex') {
            checkRawSql('raw', 'knex')
          }

          if (object.type === 'CallExpression' && object.callee.type === 'Identifier' && object.callee.name === 'require') {
            const requireArg = object.arguments[0]
            if (requireArg && requireArg.type === 'StringLiteral' && requireArg.value === 'knex') {
              checkRawSql('raw', 'knex')
            }
          }
        }
      }
    }

    return issues
  }
}
