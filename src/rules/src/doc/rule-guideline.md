# JSast 规则开发指南

## 目录

1. [项目结构](#项目结构)
2. [规则实现规范](#规则实现规范)
3. [单元测试规范](#单元测试规范)
4. [测试用例规范](#测试用例规范)
5. [示例规则](#示例规则)
6. [待实现规则](#待实现规则)

---

## 项目结构

### 规则文件目录
```
src/rules/src/
├── command-injection.ts    # 已实现的命令注入检测规则
├── console-log.ts          # 已实现的禁止console.log规则
├── no-var.ts               # 已实现的禁止var规则
├── unsafe-spawn.ts         # 已实现的不安全spawn调用检测规则
└── todo.md                 # 待实现规则列表
```

### 测试文件目录
```
src/__test__/src/
├── no-command-injection.test.ts  # 命令注入规则测试
├── no-console-log.test.ts        # console.log规则测试
├── no-unsafe-spawn.test.ts       # 不安全spawn规则测试
└── no-var.test.ts                # var规则测试
```

### 测试用例目录
```
test-case/
└── test.js  # 综合测试用例文件
```

---

## 规则实现规范

### 1. 基本结构

每个规则文件应导出一个符合 `Rule` 接口的对象：

```typescript
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 规则描述
 */
export const ruleName: Rule = {
  name: 'rule-name',
  description: '规则描述文本',
  severity: 'error' | 'warning' | 'note',
  category: 'security' | 'code-quality' | 'performance',
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

### 2. 命名规范

#### 规则命名前缀分类

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

3. **`avoid-` 前缀**: 用于建议避免某些不安全的做法
   - `avoid-raw-sql`: 避免使用原始SQL
   - `avoid-unsafe-html`: 避免不安全的HTML
   - `avoid-unsafe-fs-access`: 避免不安全的文件系统访问

4. **`use-` 前缀**: 用于建议使用更安全的替代方案
   - `use-https`: 使用HTTPS
   - `use-secure-random`: 使用安全的随机数生成器

5. **`validate-` 前缀**: 用于验证和检查
   - `validate-json-parse`: 验证JSON解析
   - `validate-redirect`: 验证重定向

### 3. 严重级别

- **`error`**: 高风险漏洞，如命令注入、SQL注入
- **`warning`**: 中风险问题，如不安全的代码实践
- **`note`**: 低风险建议，如代码质量优化

### 4. 错误信息

错误信息应包含以下内容：
1. 清晰描述问题
2. 说明潜在风险
3. 提供建议的解决方案

**示例**:
```typescript
message: 'Unsafe command execution: exec uses dynamically concatenated command string, vulnerable to command injection'
```

---

## 单元测试规范

### 1. 测试文件命名

测试文件应与规则文件同名，后缀为 `.test.ts`，位于 `src/__test__/src/` 目录下。

**示例**:
- 规则文件: `no-var.ts`
- 测试文件: `no-var.test.ts`

### 2. 测试结构

每个测试文件应包含：
1. 导入规则和测试辅助函数
2. 定义测试用例
3. 运行测试

```typescript
import { describe, it, expect } from 'bun:test'
import { testRule } from '../rule-test-helper'
import { varRule } from '../../rules/src/no-var'

describe('no-var rule', () => {
  it('should detect var declarations', () => {
    const code = 'var x = 10'
    const issues = testRule(varRule, code)
    expect(issues.length).toBe(1)
  })

  it('should not detect let declarations', () => {
    const code = 'let x = 10'
    const issues = testRule(varRule, code)
    expect(issues.length).toBe(0)
  })
})
```

---

## 测试用例规范

### 1. 测试用例文件

测试用例文件位于 `test-case/` 目录下，格式为 `.js` 文件。

### 2. 测试用例内容

每个测试用例应包含：
1. 测试场景描述
2. 测试代码
3. 预期结果

```javascript
// 测试命令注入漏洞
const child_process = require('child_process')

// 安全的：使用参数化查询
child_process.exec('ls', (err, stdout) => {
  console.log(stdout)
})

// 不安全的：动态拼接命令字符串
const userInput = '; rm -rf /'
child_process.exec('ls ' + userInput, (err, stdout) => {
  console.log(stdout)
})
```

---

## 示例规则

### 1. 简单规则示例 (no-var.ts)

```typescript
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用var关键字规则
 */
export const varRule: Rule = {
  name: 'no-var',
  description: 'Disallows the use of var keyword',
  severity: 'warning',
  category: 'code-quality',
  check(node) {
    const issues: RuleIssue[] = []
    if (node.type === 'VariableDeclaration' && node.kind === 'var' && node.loc) {
      issues.push({
        message: 'Do not use var keyword, use let or const instead',
        line: node.loc.start.line,
        column: node.loc.start.column
      })
    }
    return issues
  }
}
```

### 2. 复杂规则示例 (command-injection.ts)

```typescript
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 命令行注入检测规则
 */
export const commandInjectionRule: Rule = {
  name: 'command-injection',
  description: 'Detects command injection vulnerabilities',
  severity: 'error',
  category: 'security',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      // 检测child_process.exec调用
      if (callee.type === 'MemberExpression') {
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'child_process' &&
          callee.property.type === 'Identifier' &&
          ['exec', 'execSync', 'execFile', 'execFileSync'].includes(callee.property.name)
        ) {
          const firstArg = node.arguments[0]
          if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
            issues.push({
              message: `Unsafe command execution: ${callee.property.name} uses dynamically concatenated command string, vulnerable to command injection`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    return issues
  }
}
```

---

## 待实现规则

### 1. SQL注入检测
```typescript
// detect-sql-injection.ts
export const detectSqlInjectionRule: Rule = {
  name: 'detect-sql-injection',
  description: 'Detects SQL injection vulnerabilities',
  severity: 'error',
  category: 'security',
  check(node) {
    const issues: RuleIssue[] = []
    // 检测逻辑
    return issues
  }
}
```

### 2. XSS检测
```typescript
// avoid-dangerously-set-innerhtml.ts
export const avoidDangerouslySetInnerHtmlRule: Rule = {
  name: 'avoid-dangerously-set-innerhtml',
  description: 'Avoid using dangerouslySetInnerHTML',
  severity: 'warning',
  category: 'security',
  check(node) {
    const issues: RuleIssue[] = []
    // 检测逻辑
    return issues
  }
}
```

### 3. 不安全随机数检测
```typescript
// use-secure-random.ts
export const useSecureRandomRule: Rule = {
  name: 'use-secure-random',
  description: 'Use secure random number generation',
  severity: 'warning',
  category: 'security',
  check(node) {
    const issues: RuleIssue[] = []
    // 检测逻辑
    return issues
  }
}
```

---

## 开发流程

1. **创建规则文件**: 在 `src/rules/src/` 目录下创建新的规则文件
2. **实现规则逻辑**: 按照规范编写规则检测逻辑
3. **创建测试文件**: 在 `src/__test__/src/` 目录下创建测试文件
4. **编写测试用例**: 为规则编写单元测试
5. **添加综合测试**: 在 `test-case/` 目录下添加综合测试用例
6. **运行测试**: 使用 `bun test` 运行所有测试

---

## 注意事项

1. **性能优化**: 避免在检测逻辑中使用复杂的正则表达式或嵌套循环
2. **误报控制**: 确保规则只检测真正的安全问题，避免误报
3. **文档完善**: 为每个规则添加清晰的描述和错误信息
4. **兼容性**: 确保规则兼容不同版本的JavaScript语法

---

## 参考资源

- [ESLint 规则开发指南](https://eslint.org/docs/developer-guide/working-with-rules)
- [SARIF 标准](https://sarifweb.azurewebsites.net/)
- [OWASP Top 10](https://owasp.org/Top10/)
