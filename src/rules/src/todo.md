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
- `detect-sql-injection`: 检测直接拼接SQL字符串
  - 检测: `db.query("SELECT * FROM users WHERE id = " + userInput)`
  - 检测: `db.query(\`SELECT * FROM users WHERE id = ${userInput}\`)`
  - 建议: 使用参数化查询

- `avoid-raw-sql`: 检测使用原始SQL字符串
  - 检测: `sequelize.query("SELECT * FROM users")`
  - 建议: 使用ORM提供的查询构建器

- `detect-mongodb-injection`: 检测MongoDB注入风险
  - 检测: `db.collection.find({ $where: "this.name == '" + userInput + "'" })`
  - 检测: `db.collection.find({ name: userInput })` (未使用$eq等操作符)

---

## 3. XSS (跨站脚本攻击)

### 待实现规则
- `avoid-dangerously-set-innerhtml`: 检测不安全的innerHTML赋值
  - 检测: `element.innerHTML = userInput`
  - 检测: `document.getElementById('app').innerHTML = data`
  - 建议: 使用textContent或DOMPurify

- `avoid-unsafe-html`: 检测不安全的HTML生成
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
- `detect-path-traversal`: 检测路径遍历风险
  - 检测: `fs.readFile('../' + userInput)`
  - 检测: `fs.readFileSync(\`./${userInput}\`)`
  - 建议: 使用path.join()并验证路径

- `avoid-unsafe-fs-access`: 检测不安全的文件系统访问
  - 检测: `fs.accessSync(userInput)`
  - 检测: `fs.existsSync(userInput)`
  - 建议: 验证和规范化路径

---

## 5. 不安全的反序列化 (Insecure Deserialization)

### 待实现规则
- `validate-json-parse`: 检测不安全的JSON解析
  - 检测: `JSON.parse(userInput)` (未验证输入)
  - 建议: 使用try-catch并验证输入

- `detect-prototype-pollution`: 检测原型污染风险
  - 检测: `obj['__proto__'] = maliciousData`
  - 检测: `Object.assign(target, userInput)`
  - 建议: 使用Object.freeze或深拷贝

---

## 6. 不安全的随机数 (Insecure Randomness)

### 待实现规则
- `use-secure-random`: 检测使用Math.random()生成安全随机数
  - 检测: `const token = Math.random().toString(36)`
  - 检测: `const sessionId = Math.random()`
  - 建议: 使用crypto.randomBytes()

- `avoid-weak-crypto`: 检测弱加密算法
  - 检测: `crypto.createHash('md5')`
  - 检测: `crypto.createHash('sha1')`
  - 建议: 使用sha256或更强的算法

---

## 7. 硬编码敏感信息 (Hardcoded Secrets)

### 待实现规则
- `detect-hardcoded-secrets`: 检测硬编码的敏感信息
  - 检测: `const apiKey = 'sk-1234567890abcdef'`
  - 检测: `const password = 'admin123'`
  - 检测: `const dbUrl = 'mongodb://user:pass@localhost'`
  - 建议: 使用环境变量

- `detect-hardcoded-urls`: 检测硬编码的URL
  - 检测: `const apiUrl = 'https://api.example.com'`
  - 建议: 使用配置文件或环境变量

---

## 8. 不安全的HTTP请求 (Insecure HTTP Requests)

### 待实现规则
- `use-https`: 检测使用http而非https
  - 检测: `fetch('http://api.example.com')`
  - 检测: `axios.get('http://api.example.com')`
  - 建议: 使用https

- `avoid-ssl-verification-disabled`: 检测禁用SSL验证
  - 检测: `https.globalAgent.options.rejectUnauthorized = false`
  - 检测: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`
  - 建议: 启用SSL验证

- `validate-redirect`: 检测不安全的重定向
  - 检测: `res.redirect(userInput)`
  - 检测: `window.location.href = userInput`
  - 建议: 验证重定向URL

---

## 9. 不安全的认证和授权 (Insecure Authentication/Authorization)

### 待实现规则
- `hash-passwords`: 检测明文密码存储
  - 检测: `user.password = 'plainPassword'`
  - 检测: `db.users.insert({ password: '123456' })`
  - 建议: 使用bcrypt等哈希算法

- `enforce-strong-password`: 检测弱密码策略
  - 检测: `if (password.length < 6)`
  - 建议: 实施强密码策略

- `regenerate-session`: 检测会话固定风险
  - 检测: 未在登录后重新生成session ID
  - 建议: 登录后重新生成session

---

## 10. 不安全的依赖 (Insecure Dependencies)

### 待实现规则
- `check-outdated-dependencies`: 检测过时的依赖包
  - 建议: 使用npm audit或yarn audit

- `check-vulnerable-dependencies`: 检测已知漏洞的依赖
  - 建议: 定期更新依赖包

---

## 11. 代码质量 (Code Quality) - 已实现 ✅

### 已实现规则
- `no-var`: 禁止使用var关键字
- `no-console-log`: 禁止使用console.log

### 可扩展规则
- `no-debugger`: 禁止使用debugger语句
- `no-alert`: 禁止使用alert
- `handle-errors`: 禁止空的catch块
- `check-unused-vars`: 检测未使用的变量
- `avoid-duplicate-imports`: 检测重复的导入

---

## 12. 其他安全规则 (Other Security Rules)

### 待实现规则
- `validate-regexp`: 检测不安全的正则表达式
  - 检测可能导致ReDoS的正则表达式
  - 建议: 使用正则表达式测试工具验证

- `avoid-dynamic-assignment`: 检测不安全的赋值操作
  - 检测: `window[userInput] = value`
  - 建议: 避免动态属性赋值

- `prevent-prototype-pollution`: 检测原型污染
  - 检测: `obj.constructor.prototype[key] = value`
  - 建议: 使用Object.freeze或Map

---

## 实现优先级建议

### 高优先级 (High Priority)
1. `detect-sql-injection` - SQL注入是常见且危险的漏洞
2. `avoid-dangerously-set-innerhtml` - XSS攻击风险高
3. `no-eval` - 动态代码执行风险
4. `detect-hardcoded-secrets` - 敏感信息泄露
5. `use-https` - 中间人攻击风险

### 中优先级 (Medium Priority)
1. `detect-path-traversal` - 文件系统访问风险
2. `use-secure-random` - 密码学安全
3. `validate-json-parse` - 反序列化风险
4. `avoid-ssl-verification-disabled` - SSL/TLS安全

### 低优先级 (Low Priority)
1. `no-debugger` - 代码质量
2. `no-alert` - 用户体验
3. `handle-errors` - 错误处理质量
4. `avoid-duplicate-imports` - 代码整洁性

---

## 命名规范说明

### 规则命名前缀分类

1. **`no-` 前缀**: 用于禁止使用特定函数或语法
   - `no-var`: 禁止使用var
   - `no-console-log`: 禁止使用console.log
   - `no-eval`: 禁止使用eval
   - `no-document-write`: 禁止使用document.write

2. **`detect-` 前缀**: 用于检测潜在的安全漏洞
   - `detect-sql-injection`: 检测SQL注入
   - `detect-mongodb-injection`: 检测MongoDB注入
   - `detect-path-traversal`: 检测路径遍历
   - `detect-prototype-pollution`: 检测原型污染
   - `detect-hardcoded-secrets`: 检测硬编码敏感信息
   - `detect-hardcoded-urls`: 检测硬编码URL

3. **`avoid-` 前缀**: 用于建议避免某些不安全的做法
   - `avoid-raw-sql`: 避免使用原始SQL
   - `avoid-unsafe-html`: 避免不安全的HTML
   - `avoid-unsafe-fs-access`: 避免不安全的文件系统访问
   - `avoid-weak-crypto`: 避免弱加密算法
   - `avoid-ssl-verification-disabled`: 避免禁用SSL验证
   - `avoid-dynamic-assignment`: 避免动态赋值
   - `avoid-duplicate-imports`: 避免重复导入

4. **`use-` 前缀**: 用于建议使用更安全的替代方案
   - `use-https`: 使用HTTPS
   - `use-secure-random`: 使用安全的随机数生成器

5. **`validate-` 前缀**: 用于验证和检查
   - `validate-json-parse`: 验证JSON解析
   - `validate-redirect`: 验证重定向
   - `validate-regexp`: 验证正则表达式

6. **`check-` 前缀**: 用于检查和审计
   - `check-outdated-dependencies`: 检查过时的依赖
   - `check-vulnerable-dependencies`: 检查有漏洞的依赖
   - `check-unused-vars`: 检查未使用的变量

7. **`enforce-` 前缀**: 用于强制执行某些策略
   - `enforce-strong-password`: 强制执行强密码策略

8. **`hash-` 前缀**: 用于加密相关的建议
   - `hash-passwords`: 哈希密码

9. **`regenerate-` 前缀**: 用于重新生成某些资源
   - `regenerate-session`: 重新生成会话

10. **`prevent-` 前缀**: 用于预防某些安全问题
    - `prevent-prototype-pollution`: 预防原型污染

11. **`handle-` 前缀**: 用于处理某些情况
    - `handle-errors`: 处理错误

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
