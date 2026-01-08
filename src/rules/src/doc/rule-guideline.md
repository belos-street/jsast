# JSast 规则开发指南

## 目录

1. [项目结构](#项目结构)
2. [规则实现规范](#规则实现规范)
3. [单元测试规范](#单元测试规范)
4. [测试用例规范](#测试用例规范)
5. [测试和结果校验](#测试和结果校验)
6. [示例规则](#示例规则)
7. [开发流程](#开发流程)
8. [注意事项](#注意事项)
9. [参考资源](#参考资源)

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
├── test.js              # 综合测试用例文件（可选）
├── no-var.js            # no-var规则测试用例
├── no-console-log.js    # no-console-log规则测试用例
├── command-injection.js # command-injection规则测试用例
└── no-unsafe-spawn.js   # no-unsafe-spawn规则测试用例
```

**建议**: 为每个规则创建独立的测试用例文件，文件名与规则名称对应，便于维护和查找。

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

### 2. 测试优先开发

新规则开发应遵循测试优先原则：

1. **首先创建测试文件**: 在实现规则之前，先编写测试用例明确预期行为
2. **运行测试验证**: 使用 `bun test` 运行测试，此时测试应失败（规则未实现）
3. **实现规则逻辑**: 编写规则代码使测试通过
4. **补充边界测试**: 添加更多边界情况和错误用例

### 3. 测试结构

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

### 4. 运行测试

使用 Bun 包管理器运行测试：

```bash
# 运行所有测试
bun test

# 运行特定规则的测试
bun test src/__test__/src/no-var.test.ts
```

---

## 测试用例规范

### 1. 测试用例文件

测试用例文件位于 `test-case/` 目录下，格式为 `.js` 文件。建议为每个规则创建独立的测试用例文件。

### 2. 测试用例内容

每个测试用例应包含：
1. 测试场景描述（注释说明）
2. 测试代码
3. 预期结果说明

### 3. 文件命名规范

测试用例文件应与规则名称对应：
- `no-var.js` 对应 `no-var` 规则
- `no-console-log.js` 对应 `no-console-log` 规则
- `command-injection.js` 对应 `command-injection` 规则
- `no-unsafe-spawn.js` 对应 `no-unsafe-spawn` 规则

**示例**:
```javascript
// test-case/no-unsafe-shell.js

// 场景1: 检测shell: true选项
// 预期: 触发no-unsafe-shell规则警告
child_process.spawn('ls', { shell: true })

// 场景2: 检测shell路径字符串
// 预期: 触发no-unsafe-shell规则警告
execSync('cat file.txt', { shell: '/bin/bash' })

// 场景3: 不使用shell选项（安全）
// 预期: 不触发规则警告
spawn('ls', ['-la'])
```

---

## 测试和结果校验

### 1. 创建规则配置文件

在 `lib/` 目录下创建 `rule.json` 文件，用于配置需要启用的规则：

```json
{
    "rules": {
        "no-console-log": 1,
        "no-var": 1,
        "command-injection": 1,
        "no-unsafe-spawn": 1,
        "no-unsafe-shell": 1,
        "detect-sql-injection": 1
    }
}
```

**配置说明**:
- 规则名称作为 key，值为 `1` 表示启用该规则
- 添加新规则时，需要在 `rules` 对象中添加对应的配置项
- 规则名称必须与规则文件中的 `name` 属性保持一致

### 2. 运行测试

使用以下命令对测试用例目录进行测试：

```bash
bun run src/main.ts -p ./test-case -r .\lib\rule.json
```

**参数说明**:
- `-p ./test-case`: 指定测试用例文件所在的目录
- `-r .\lib\rule.json`: 指定规则配置文件的路径

### 3. 结果校验

测试完成后，检查输出结果是否符合预期：

1. **检查检测到的安全问题**:
   - 确认所有预期的安全问题都被检测到
   - 验证错误信息的准确性和清晰度
   - 确认行号和列号正确

2. **检查误报情况**:
   - 确认安全的代码没有被误报
   - 验证规则不会对正常的代码产生误判

3. **检查漏报情况**:
   - 确认所有应该被检测的问题都被发现
   - 验证规则覆盖了所有预期的场景

4. **输出格式验证**:
   - 检查输出是否符合 SARIF 格式（如果使用 SARIF 输出）
   - 确认结果文件可以正确解析和显示

### 4. 测试用例验证清单

在完成测试后，使用以下清单验证测试用例的完整性：

- [ ] 所有不安全的代码都被检测到
- [ ] 所有安全的代码都没有被误报
- [ ] 错误信息清晰明确
- [ ] 行号和列号准确
- [ ] 边界情况都被覆盖
- [ ] 多种使用模式都被测试
- [ ] 规则配置正确加载
- [ ] 输出格式符合预期

### 5. 常见问题排查

**问题1: 规则未被触发**
- 检查 `rule.json` 中是否正确配置了规则名称
- 确认规则已在 `src/rules/src/index.ts` 中注册
- 验证规则名称在 `RuleName` 类型中已定义

**问题2: 误报过多**
- 检查规则的检测逻辑是否过于宽松
- 考虑添加更多的条件判断来减少误报
- 参考其他已实现规则的实现方式

**问题3: 漏报问题**
- 检查规则的检测逻辑是否覆盖了所有场景
- 添加更多的测试用例来覆盖边界情况
- 考虑使用更复杂的 AST 分析来提高检测准确性

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

### 标准开发顺序

新规则的开发应按照以下顺序进行：

1. **创建单元测试文件**: 首先在 `src/__test__/src/` 目录下创建规则对应的测试文件
2. **实现规则逻辑**: 在 `src/rules/src/` 目录下创建规则文件并实现检测逻辑
3. **添加类型定义**: 在 `src/rules/type.ts` 的 `RuleName` 类型中添加规则名称
4. **注册规则**: 在 `src/rules/src/index.ts` 中导入并注册规则
5. **添加综合测试**: 在 `test-case/` 目录下创建对应的测试用例文件
6. **运行测试**: 使用 `bun test` 运行测试验证功能

### 规则注册规范

在 `src/rules/src/index.ts` 中注册新规则：

```typescript
import { noUnsafeShellRule } from './no-unsafe-shell'

export const ruleSet = [
  noConsoleLogRule,
  varRule,
  commandInjectionRule,
  unsafeSpawnRule,
  noUnsafeShellRule  // 新规则添加到规则集末尾
]
```

**注意**: 规则应添加到 `ruleSet` 数组的末尾，确保新规则被正确加载。

### 类型定义规范

在实现新规则后，需要在 `src/rules/type.ts` 中更新 `RuleName` 类型：

```typescript
export type RuleName = 'no-console-log' | 'no-var' | 'command-injection' | 'no-unsafe-spawn' | 'your-new-rule'
```

**注意**: 规则名称必须与规则文件中的 `name` 属性保持一致。

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
