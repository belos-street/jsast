// 场景1: 检测API密钥（sk-前缀）
// 预期: 触发detect-hardcoded-secrets规则警告
const apiKey1 = 'sk-1234567890abcdef'

// 场景2: 检测API密钥（pk-前缀）
// 预期: 触发detect-hardcoded-secrets规则警告
const publicKey = 'pk-1234567890abcdef'

// 场景3: 检测Bearer token
// 预期: 触发detect-hardcoded-secrets规则警告
const bearerToken = 'Bearer 1234567890abcdef'

// 场景4: 检测API_KEY_前缀的密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const apikey = 'API_KEY_1234567890abcdef'

// 场景5: 检测JWT token
// 预期: 触发detect-hardcoded-secrets规则警告
const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

// 场景6: 检测AWS访问密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const awsAccessKey = 'AKIA1234567890123456'

// 场景7: 检测AWS密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const awsSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

// 场景8: 检测GitHub个人访问令牌
// 预期: 触发detect-hardcoded-secrets规则警告
const githubToken = 'ghp_1234567890abcdef1234567890abcdef'

// 场景9: 检测Slack API令牌
// 预期: 触发detect-hardcoded-secrets规则警告
const slackToken = 'xoxb-1234567890-1234567890-1234567890abcdef123456'

// 场景10: 检测Stripe API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const stripeKey = 'sk_test_1234567890abcdef1234567890'

// 场景11: 检测Firebase/Google API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const firebaseKey = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe'

// 场景12: 检测Twilio API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const twilioKey = 'SK1234567890abcdef1234567890abcdef'

// 场景13: 检测SendGrid API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const sendGridKey = 'SG.1234567890abcdef123456.1234567890abcdef1234567890abcdef1234567890abc'

// 场景14: 检测Mailgun API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const mailgunKey = 'key-1234567890abcdef1234567890abcdef'

// 场景15: 检测Datadog API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const datadogKey = '1234567890abcdef1234567890abcdef'

// 场景16: 检测New Relic许可证密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const newRelicKey = '1234567890abcdef1234567890abcdef12345678'

// 场景17: 检测PagerDuty API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const pagerDutyKey = '1234567890abcdef1234'

// 场景18: 检测Rollbar访问令牌
// 预期: 触发detect-hardcoded-secrets规则警告
const rollbarKey = '1234567890abcdef1234567890abcdef'

// 场景19: 检测Sentry DSN
// 预期: 触发detect-hardcoded-secrets规则警告
const sentryDsn = 'https://1234567890abcdef@sentry.io/123456'

// 场景20: 检测MongoDB连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const mongoUrl = 'mongodb://user:password@localhost:27017/mydb'

// 场景21: 检测PostgreSQL连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const postgresUrl = 'postgresql://user:password@localhost:5432/mydb'

// 场景22: 检测MySQL连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const mysqlUrl = 'mysql://user:password@localhost:3306/mydb'

// 场景23: 检测Redis连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const redisUrl = 'redis://:password@localhost:6379'

// 场景24: 检测HTTP连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const httpUrl = 'http://user:password@localhost:8080'

// 场景25: 检测HTTPS连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const httpsUrl = 'https://user:password@localhost:8443'

// 场景26: 检测FTP连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const ftpUrl = 'ftp://user:password@ftp.example.com'

// 场景27: 检测SFTP连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const sftpUrl = 'sftp://user:password@sftp.example.com'

// 场景28: 检测SMTP连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const smtpUrl = 'smtp://user:password@smtp.example.com:587'

// 场景29: 检测IMAP连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const imapUrl = 'imap://user:password@imap.example.com:993'

// 场景30: 检测POP3连接字符串（带密码）
// 预期: 触发detect-hardcoded-secrets规则警告
const pop3Url = 'pop3://user:password@pop3.example.com:995'

// 场景31: 检测对象中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const config1 = { apiKey: 'sk-1234567890abcdef' }

// 场景32: 检测对象中的数据库URL
// 预期: 触发detect-hardcoded-secrets规则警告
const dbConfig = { url: 'mongodb://user:pass@localhost' }

// 场景33: 检测函数调用中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
client.setApiKey('sk-1234567890abcdef')

// 场景34: 检测函数调用中的数据库URL
// 预期: 触发detect-hardcoded-secrets规则警告
connect('mongodb://user:pass@localhost')

// 场景35: 检测数组中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const keys = ['sk-1234567890abcdef', 'pk-1234567890abcdef']

// 场景36: 检测嵌套对象中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const nestedConfig = { api: { key: 'sk-1234567890abcdef' } }

// 场景37: 检测模板字符串中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const templateKey = `sk-1234567890abcdef`

// 场景38: 检测条件判断中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
if (apiKey === 'sk-1234567890abcdef') {
  console.log('match')
}

// 场景39: 检测循环中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
for (let i = 0; i < 10; i++) {
  console.log('sk-1234567890abcdef')
}

// 场景40: 检测try-catch中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
try {
  const key = 'sk-1234567890abcdef'
} catch (e) {
  console.error(e)
}

// 场景41: 检测switch语句中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
switch (apiKey) {
  case 'sk-1234567890abcdef':
    console.log('match')
    break
}

// 场景42: 检测三元运算符中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const result = condition ? 'sk-1234567890abcdef' : 'pk-1234567890abcdef'

// 场景43: 检测await表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const awaited = await Promise.resolve('sk-1234567890abcdef')

// 场景44: 检测new表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const client = new Client('sk-1234567890abcdef')

// 场景45: 检测展开运算符中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const spreaded = [...['sk-1234567890abcdef']]

// 场景46: 检测计算属性中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const computed = { ['sk-1234567890abcdef']: 'value' }

// 场景47: 检测默认参数中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
function getDefault(key = 'sk-1234567890abcdef') {
  return key
}

// 场景48: 检测throw语句中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
throw new Error('sk-1234567890abcdef')

// 场景49: 检测yield表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
function* generator() {
  yield 'sk-1234567890abcdef'
}

// 场景50: 检测yield*表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
function* generator2() {
  yield* ['sk-1234567890abcdef']
}

// 场景51: 检测this表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
this.apiKey = 'sk-1234567890abcdef'

// 场景52: 检测super调用中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
class Child extends Parent {
  constructor() {
    super('sk-1234567890abcdef')
  }
}

// 场景53: 检测序列表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const seq = (console.log('test'), 'sk-1234567890abcdef')

// 场景54: 检测更新表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
let apiKey2
apiKey2 = 'sk-1234567890abcdef'

// 场景55: 检测一元表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const positive = +'sk-1234567890abcdef'

// 场景56: 检测逻辑表达式中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const logical = 'sk-1234567890abcdef' || null

// 场景57: 检测可选链中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const optional = config?.apiKey || 'sk-1234567890abcdef'

// 场景58: 检测空值合并中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
const coalesced = config?.apiKey ?? 'sk-1234567890abcdef'

// 场景59: 检测二进制表达式中的API密钥
// 预期: 不触发detect-hardcoded-secrets规则警告（字符串拼接）
const binary = 'sk-' + '1234567890abcdef'

// 场景60: 检测多个硬编码密钥
// 预期: 触发detect-hardcoded-secrets规则警告（2次）
const key1 = 'sk-1234567890abcdef'
const key2 = 'pk-1234567890abcdef'

// 场景61: 检测export中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
export const exportedKey = 'sk-1234567890abcdef'

// 场景62: 检测default export中的API密钥
// 预期: 触发detect-hardcoded-secrets规则警告
export default { apiKey: 'sk-1234567890abcdef' }

// 场景63: 不检测环境变量（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const envApiKey = process.env.API_KEY

// 场景64: 不检测环境变量与fallback（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const fallbackApiKey = process.env.API_KEY || 'default'

// 场景65: 不检测空字符串（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const emptyPassword = ''

// 场景66: 不检测短字符串（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const shortPassword = '123'

// 场景67: 不检测占位符（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const placeholderPassword = 'your_password_here'

// 场景68: 不检测示例值（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const exampleApiKey = 'your-api-key-here'

// 场景69: 不检测localhost URL（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const localUrl = 'mongodb://localhost:27017/mydb'

// 场景70: 不检测生产URL（无凭据）（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const prodUrl = 'https://api.example.com'

// 场景71: 不检测模板字符串中的环境变量（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const templateDbUrl = `mongodb://${process.env.DB_USER}:${process.env.DB_PASS}@localhost`

// 场景72: 不检测配置文件引用（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
const config = require('./config.json')

// 场景73: 不检测import语句（安全）
// 预期: 不触发detect-hardcoded-secrets规则警告
import { config } from './config'
