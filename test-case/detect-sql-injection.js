// detect-sql-injection 测试用例
// 场景1: MySQL 查询使用模板字符串（不安全）
// 预期: 触发 detect-sql-injection 规则警告
mysql.query(`SELECT * FROM users WHERE id = ${userInput}`)

// 场景2: MySQL 查询使用字符串拼接（不安全）
// 预期: 触发 detect-sql-injection 规则警告
mysql.query('SELECT * FROM users WHERE name = ' + userName)

// 场景3: PostgreSQL 查询使用模板字符串（不安全）
// 预期: 触发 detect-sql-injection 规则警告
client.query(`SELECT * FROM products WHERE price > ${price}`)

// 场景4: SQLite 查询使用模板字符串（不安全）
// 预期: 触发 detect-sql-injection 规则警告
db.run(`UPDATE users SET name = '${name}' WHERE id = ${id}`)

// 场景5: Sequelize 查询使用模板字符串（不安全）
// 预期: 触发 detect-sql-injection 规则警告
sequelize.query(`SELECT * FROM orders WHERE status = '${status}'`)

// 场景6: 使用参数化查询（安全）
// 预期: 不触发规则警告
mysql.query('SELECT * FROM users WHERE id = ?', [userId])

// 场景7: 使用静态 SQL 字符串（安全）
// 预期: 不触发规则警告
mysql.query('SELECT * FROM users')

// 场景8: PostgreSQL 使用命名参数（安全）
// 预期: 不触发规则警告
pg.query('SELECT * FROM users WHERE id = $1', [userId])

// 场景9: 多个不安全的 SQL 查询
// 预期: 触发多个 detect-sql-injection 规则警告
mysql.query(`SELECT * FROM users WHERE id = ${id}`)
pg.query(`SELECT * FROM products WHERE name = '${name}'`)

// 场景10: require mysql 模式（不安全）
// 预期: 触发 detect-sql-injection 规则警告
require('mysql').query(`SELECT * FROM users WHERE id = ${id}`)

// 场景11: require pg 模式（不安全）
// 预期: 触发 detect-sql-injection 规则警告
require('pg').Client().query(`SELECT * FROM users WHERE id = ${id}`)

// 场景12: require sqlite3 模式（不安全）
// 预期: 触发 detect-sql-injection 规则警告
require('sqlite3').Database().run(`UPDATE users SET name = '${name}'`)

// 场景13: new pg.Client().query() 模式（不安全）
// 预期: 触发 detect-sql-injection 规则警告
new pg.Client().query(`INSERT INTO users (name) VALUES ('${name}')`)

// 场景14: Mongoose where 查询（不安全）
// 预期: 触发 detect-sql-injection 规则警告
User.where(`name = ${name}`)

// 场景15: 直接调用 query 函数（不安全）
// 预期: 触发 detect-sql-injection 规则警告
query(`SELECT * FROM users WHERE id = ${id}`)

// 场景16: 静态模板字符串（安全）
// 预期: 不触发规则警告
mysql.query(`SELECT * FROM users WHERE status = 'active'`)

// 场景17: console.log 不会触发 SQL 注入检测（安全）
// 预期: 不触发规则警告
console.log('SELECT * FROM users')
