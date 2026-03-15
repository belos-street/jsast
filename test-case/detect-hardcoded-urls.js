// 场景1: 检测硬编码HTTP URL
// 预期: 触发detect-hardcoded-urls规则警告
const apiUrl = 'http://api.example.com'

// 场景2: 检测硬编码HTTPS URL
// 预期: 触发detect-hardcoded-urls规则警告
const secureApiUrl = 'https://api.example.com'

// 场景3: 检测硬编码API endpoint
// 预期: 触发detect-hardcoded-urls规则警告
const endpoint = 'https://api.github.com/users'

// 场景4: 检测硬编码数据库URL
// 预期: 触发detect-hardcoded-urls规则警告
const dbUrl = 'mongodb://localhost:27017/mydb'

// 场景5: 检测硬编码Redis URL
// 预期: 触发detect-hardcoded-urls规则警告
const redisUrl = 'redis://localhost:6379'

// 场景6: 检测硬编码FTP URL
// 预期: 触发detect-hardcoded-urls规则警告
const ftpUrl = 'ftp://example.com/files'

// 场景7: 检测硬编码SFTP URL
// 预期: 触发detect-hardcoded-urls规则警告
const sftpUrl = 'sftp://example.com/files'

// 场景8: 检测硬编码WebSocket URL
// 预期: 触发detect-hardcoded-urls规则警告
const wsUrl = 'ws://example.com/socket'

// 场景9: 检测硬编码安全WebSocket URL
// 预期: 触发detect-hardcoded-urls规则警告
const wssUrl = 'wss://example.com/socket'

// 场景10: 检测硬编码localhost URL
// 预期: 触发detect-hardcoded-urls规则警告
const localhostUrl = 'http://localhost:3000'

// 场景11: 检测硬编码127.0.0.1 URL
// 预期: 触发detect-hardcoded-urls规则警告
const localIpUrl = 'http://127.0.0.1:3000'

// 场景12: 检测硬编码URL在对象属性中
// 预期: 触发detect-hardcoded-urls规则警告
const config = { apiUrl: 'https://api.example.com' }

// 场景13: 检测硬编码URL在数组中
// 预期: 触发detect-hardcoded-urls规则警告
const urls = ['https://api.example.com', 'https://backup.example.com']

// 场景14: 检测硬编码URL在函数调用中
// 预期: 触发detect-hardcoded-urls规则警告
fetch('https://api.example.com/data')

// 场景15: 检测硬编码URL在模板字符串中
// 预期: 触发detect-hardcoded-urls规则警告
const templateUrl = `https://api.example.com`

// 场景16: 不检测环境变量（安全）
// 预期: 不触发规则警告
const envApiUrl = process.env.API_URL

// 场景17: 不检测相对路径（安全）
// 预期: 不触发规则警告
const relativeUrl = '/api/users'

// 场景18: 不检测空字符串（安全）
// 预期: 不触发规则警告
const emptyUrl = ''

// 场景19: 不检测短字符串（安全）
// 预期: 不触发规则警告
const shortUrl = 'http'

// 场景20: 不检测file://协议（安全）
// 预期: 不触发规则警告
const fileUrl = 'file:///path/to/file'

// 场景21: 不检测data: URLs（安全）
// 预期: 不触发规则警告
const dataUrl = 'data:text/plain;base64,SGVsbG8='

// 场景22: 不检测mailto: URLs（安全）
// 预期: 不触发规则警告
const email = 'mailto:user@example.com'

// 场景23: 不检测占位符（安全）
// 预期: 不触发规则警告
const placeholderUrl = 'your-api-url-here'
