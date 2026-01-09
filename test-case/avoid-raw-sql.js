// avoid-raw-sql 测试用例
// 场景1: Sequelize 使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('SELECT * FROM users')

// 场景2: Sequelize 使用模板字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query(`SELECT * FROM users WHERE id = ${userId}`)

// 场景3: Sequelize 使用字符串拼接（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('SELECT * FROM users WHERE name = ' + name)

// 场景4: Sequelize INSERT 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('INSERT INTO users (name, email) VALUES ("John", "john@example.com")')

// 场景5: Sequelize UPDATE 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('UPDATE users SET status = "active"')

// 场景6: Sequelize DELETE 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('DELETE FROM users WHERE id = 1')

// 场景7: Sequelize CREATE TABLE 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(255))')

// 场景8: Sequelize DROP TABLE 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('DROP TABLE IF EXISTS users')

// 场景9: Sequelize ALTER TABLE 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sequelize.query('ALTER TABLE users ADD COLUMN age INT')

// 场景10: TypeORM 使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
connection.query('SELECT * FROM users')

// 场景11: TypeORM 使用模板字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
connection.query(`SELECT * FROM users WHERE id = ${userId}`)

// 场景12: TypeORM INSERT 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
connection.query('INSERT INTO users (name) VALUES ("John")')

// 场景13: Knex.raw 使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
knex.raw('SELECT * FROM users')

// 场景14: Knex.raw 使用模板字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
knex.raw(`SELECT * FROM users WHERE id = ${userId}`)

// 场景15: Knex.raw 使用字符串拼接（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
knex.raw('SELECT * FROM users WHERE name = ' + name)

// 场景16: Knex.raw INSERT 语句（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
knex.raw('INSERT INTO users (name) VALUES ("John")')

// 场景17: Prisma $queryRaw 使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
prisma.$queryRaw`SELECT * FROM users`

// 场景18: Prisma $queryRaw 使用动态内容（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`

// 场景19: Prisma $executeRaw 使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
prisma.$executeRaw`INSERT INTO users (name) VALUES ('John')`

// 场景20: MySQL 直接使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
mysql.query('SELECT * FROM users')

// 场景21: PostgreSQL 直接使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
pg.query('SELECT * FROM users')

// 场景22: SQLite3 直接使用原始 SQL 字符串（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
sqlite3.run('SELECT * FROM users')

// 场景23: Sequelize 使用查询构建器（推荐）
// 预期: 不触发规则警告
User.findAll({ where: { id: userId } })

// 场景24: Sequelize 使用 findOne 方法（推荐）
// 预期: 不触发规则警告
User.findOne({ where: { email: userEmail } })

// 场景25: Sequelize 使用 create 方法（推荐）
// 预期: 不触发规则警告
User.create({ name: 'John', email: 'john@example.com' })

// 场景26: Sequelize 使用 update 方法（推荐）
// 预期: 不触发规则警告
User.update({ status: 'active' }, { where: { id: userId } })

// 场景27: Sequelize 使用 destroy 方法（推荐）
// 预期: 不触发规则警告
User.destroy({ where: { id: userId } })

// 场景28: TypeORM 使用 find 方法（推荐）
// 预期: 不触发规则警告
userRepository.find({ where: { id: userId } })

// 场景29: TypeORM 使用 findOne 方法（推荐）
// 预期: 不触发规则警告
userRepository.findOne({ where: { id: userId } })

// 场景30: TypeORM 使用 save 方法（推荐）
// 预期: 不触发规则警告
userRepository.save(user)

// 场景31: TypeORM 使用 remove 方法（推荐）
// 预期: 不触发规则警告
userRepository.remove(user)

// 场景32: Prisma 使用 findMany 方法（推荐）
// 预期: 不触发规则警告
prisma.user.findMany({ where: { id: userId } })

// 场景33: Prisma 使用 findUnique 方法（推荐）
// 预期: 不触发规则警告
prisma.user.findUnique({ where: { id: userId } })

// 场景34: Prisma 使用 create 方法（推荐）
// 预期: 不触发规则警告
prisma.user.create({ data: { name: 'John' } })

// 场景35: Prisma 使用 update 方法（推荐）
// 预期: 不触发规则警告
prisma.user.update({ where: { id: userId }, data: { status: 'active' } })

// 场景36: Prisma 使用 delete 方法（推荐）
// 预期: 不触发规则警告
prisma.user.delete({ where: { id: userId } })

// 场景37: Knex 使用查询构建器（推荐）
// 预期: 不触发规则警告
knex('users').select('*').where('id', userId)

// 场景38: Knex 使用 insert 方法（推荐）
// 预期: 不触发规则警告
knex('users').insert({ name: 'John', email: 'john@example.com' })

// 场景39: Knex 使用 update 方法（推荐）
// 预期: 不触发规则警告
knex('users').where('id', userId).update({ status: 'active' })

// 场景40: Knex 使用 delete 方法（推荐）
// 预期: 不触发规则警告
knex('users').where('id', userId).del()

// 场景41: require sequelize 模式（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
require('sequelize').query('SELECT * FROM users')

// 场景42: require knex 模式（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
require('knex').raw('SELECT * FROM users')

// 场景43: require mysql 模式（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
require('mysql').query('SELECT * FROM users')

// 场景44: require pg 模式（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
require('pg').query('SELECT * FROM users')

// 场景45: require sqlite3 模式（不推荐）
// 预期: 触发 avoid-raw-sql 规则警告
require('sqlite3').run('SELECT * FROM users')

// 场景46: 多个原始 SQL 查询
// 预期: 触发多个 avoid-raw-sql 规则警告
sequelize.query('SELECT * FROM users')
sequelize.query('SELECT * FROM products')

// 场景47: 混合不同 ORM 的原始 SQL 查询
// 预期: 触发多个 avoid-raw-sql 规则警告
sequelize.query('SELECT * FROM users')
knex.raw('SELECT * FROM products')

// 场景48: 空字符串（安全）
// 预期: 不触发规则警告
sequelize.query('')

// 场景49: 非 SQL 字符串（安全）
// 预期: 不触发规则警告
sequelize.query('Hello World')

// 场景50: console.log 不会触发原始 SQL 检测（安全）
// 预期: 不触发规则警告
console.log('SELECT * FROM users')
