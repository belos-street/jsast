# 安全规则分类实现计划

## 1. 命令注入 (Command Injection) - 已实现 ✅

### 已实现规则
- `no-command-injection`: 检测不安全的child_process函数调用

### 可扩展规则
- `no-unsafe-spawn`: 检测不安全的spawn调用
- `no-unsafe-shell`: 检测使用shell选项的命令执行

---

## 2. SQL注入 (SQL Injection)

### 待实现规则
- `no-sql-injection`: 检测直接拼接SQL字符串
  - 检测: `db.query("SELECT * FROM users WHERE id = " + userInput)`
  - 检测: `db.query(\`SELECT * FROM users WHERE id = ${userInput}\`)`
  - 建议: 使用参数化查询

- `no-raw-sql`: 检测使用原始SQL字符串
  - 检测: `sequelize.query("SELECT * FROM users")`
  - 建议: 使用ORM提供的查询构建器

- `no-mongodb-injection`: 检测MongoDB注入风险
  - 检测: `db.collection.find({ $where: "this.name == '" + userInput + "'" })`
  - 检测: `db.collection.find({ name: userInput })` (未使用$eq等操作符)

---

## 3. XSS (跨站脚本攻击)

### 待实现规则
- `no-dangerously-set-innerhtml`: 检测不安全的innerHTML赋值
  - 检测: `element.innerHTML = userInput`
  - 检测: `document.getElementById('app').innerHTML = data`
  - 建议: 使用textContent或DOMPurify

- `no-unsafe-html`: 检测不安全的HTML生成
  - 检测: `res.send('<div>' + userInput + '</div>')`
  - 检测: `return <div>{userInput}</div>` (React中未转义)

- `no-eval`: 检测eval函数使用
  - 检测: `eval(userInput)`
  - 检测: `setTimeout(userInput, 1000)`
  - 检测: `setInterval(userInput, 1000)`
  - 建议: 避免使用动态代码执行

- `no-document-write`: 检测document.write使用
  - 检测: `document.write(userInput)`
  - 建议: 使用DOM操作方法

---

## 4. 路径遍历 (Path Traversal)

### 待实现规则
- `no-path-traversal`: 检测路径遍历风险
  - 检测: `fs.readFile('../' + userInput)`
  - 检测: `fs.readFileSync(\`./${userInput}\`)`
  - 建议: 使用path.join()并验证路径

- `no-unsafe-fs-access`: 检测不安全的文件系统访问
  - 检测: `fs.accessSync(userInput)`
  - 检测: `fs.existsSync(userInput)`
  - 建议: 验证和规范化路径

---

## 5. 不安全的反序列化 (Insecure Deserialization)

### 待实现规则
- `no-unsafe-json-parse`: 检测不安全的JSON解析
  - 检测: `JSON.parse(userInput)` (未验证输入)
  - 建议: 使用try-catch并验证输入

- `no-unsafe-prototype-pollution`: 检测原型污染风险
  - 检测: `obj['__proto__'] = maliciousData`
  - 检测: `Object.assign(target, userInput)`
  - 建议: 使用Object.freeze或深拷贝

---

## 6. 不安全的随机数 (Insecure Randomness)

### 待实现规则
- `no-insecure-random`: 检测使用Math.random()生成安全随机数
  - 检测: `const token = Math.random().toString(36)`
  - 检测: `const sessionId = Math.random()`
  - 建议: 使用crypto.randomBytes()

- `no-weak-crypto`: 检测弱加密算法
  - 检测: `crypto.createHash('md5')`
  - 检测: `crypto.createHash('sha1')`
  - 建议: 使用sha256或更强的算法

---

## 7. 硬编码敏感信息 (Hardcoded Secrets)

### 待实现规则
- `no-hardcoded-secrets`: 检测硬编码的敏感信息
  - 检测: `const apiKey = 'sk-1234567890abcdef'`
  - 检测: `const password = 'admin123'`
  - 检测: `const dbUrl = 'mongodb://user:pass@localhost'`
  - 建议: 使用环境变量

- `no-hardcoded-urls`: 检测硬编码的URL
  - 检测: `const apiUrl = 'https://api.example.com'`
  - 建议: 使用配置文件或环境变量

---

## 8. 不安全的HTTP请求 (Insecure HTTP Requests)

### 待实现规则
- `no-insecure-http`: 检测使用http而非https
  - 检测: `fetch('http://api.example.com')`
  - 检测: `axios.get('http://api.example.com')`
  - 建议: 使用https

- `no-ssl-verification-disabled`: 检测禁用SSL验证
  - 检测: `https.globalAgent.options.rejectUnauthorized = false`
  - 检测: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`
  - 建议: 启用SSL验证

- `no-unsafe-redirect`: 检测不安全的重定向
  - 检测: `res.redirect(userInput)`
  - 检测: `window.location.href = userInput`
  - 建议: 验证重定向URL

---

## 9. 不安全的认证和授权 (Insecure Authentication/Authorization)

### 待实现规则
- `no-plaintext-password`: 检测明文密码存储
  - 检测: `user.password = 'plainPassword'`
  - 检测: `db.users.insert({ password: '123456' })`
  - 建议: 使用bcrypt等哈希算法

- `no-weak-password-policy`: 检测弱密码策略
  - 检测: `if (password.length < 6)`
  - 建议: 实施强密码策略

- `no-session-fixation`: 检测会话固定风险
  - 检测: 未在登录后重新生成session ID
  - 建议: 登录后重新生成session

---

## 10. 不安全的依赖 (Insecure Dependencies)

### 待实现规则
- `no-outdated-dependencies`: 检测过时的依赖包
  - 建议: 使用npm audit或yarn audit

- `no-vulnerable-dependencies`: 检测已知漏洞的依赖
  - 建议: 定期更新依赖包

---

## 11. 代码质量 (Code Quality) - 已实现 ✅

### 已实现规则
- `no-var`: 禁止使用var关键字
- `no-console-log`: 禁止使用console.log

### 可扩展规则
- `no-debugger`: 禁止使用debugger语句
- `no-alert`: 禁止使用alert
- `no-empty-catch`: 禁止空的catch块
- `no-unused-vars`: 检测未使用的变量
- `no-duplicate-imports`: 检测重复的导入

---

## 12. 其他安全规则 (Other Security Rules)

### 待实现规则
- `no-unsafe-regexp`: 检测不安全的正则表达式
  - 检测可能导致ReDoS的正则表达式
  - 建议: 使用正则表达式测试工具验证

- `no-unsafe-assignment`: 检测不安全的赋值操作
  - 检测: `window[userInput] = value`
  - 建议: 避免动态属性赋值

- `no-prototype-pollution`: 检测原型污染
  - 检测: `obj.constructor.prototype[key] = value`
  - 建议: 使用Object.freeze或Map

---

## 实现优先级建议

### 高优先级 (High Priority)
1. `no-sql-injection` - SQL注入是常见且危险的漏洞
2. `no-dangerously-set-innerhtml` - XSS攻击风险高
3. `no-eval` - 动态代码执行风险
4. `no-hardcoded-secrets` - 敏感信息泄露
5. `no-insecure-http` - 中间人攻击风险

### 中优先级 (Medium Priority)
1. `no-path-traversal` - 文件系统访问风险
2. `no-insecure-random` - 密码学安全
3. `no-unsafe-json-parse` - 反序列化风险
4. `no-ssl-verification-disabled` - SSL/TLS安全

### 低优先级 (Low Priority)
1. `no-debugger` - 代码质量
2. `no-alert` - 用户体验
3. `no-empty-catch` - 错误处理质量
4. `no-duplicate-imports` - 代码整洁性

---

## 实现模板参考

基于已有的`no-command-injection`规则，新规则应遵循以下模式：

```typescript
import type { Rule } from '..'
import type { RuleIssue } from '../type'

export const newSecurityRule: Rule = {
  name: 'rule-name',
  description: '规则描述',
  severity: 'high' | 'medium' | 'low',
  check(node) {
    const issues: RuleIssue[] = []

    // 检测逻辑
    if (node.type === 'NodeType' && condition) {
      issues.push({
        message: '问题描述',
        line: node.loc?.start.line || 0,
        column: node.loc?.start.column || 0
      })
    }

    return issues
  }
}
```

---

## 注意事项

1. **规则命名规范**: 使用`no-`前缀表示禁止的行为
2. **严重级别**: 根据漏洞影响范围确定high/medium/low
3. **错误信息**: 清晰描述问题和建议的解决方案
4. **测试覆盖**: 每个规则都需要对应的测试用例
5. **文档**: 为每个规则编写详细的使用说明
