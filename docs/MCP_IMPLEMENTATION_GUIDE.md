# JSAST MCP 服务器实现指南

## 目录
1. [MCP 简介](#mcp-简介)
2. [为什么需要 MCP](#为什么需要-mcp)
3. [架构设计](#架构设计)
4. [实现步骤](#实现步骤)
5. [配置和使用](#配置和使用)
6. [示例](#示例)
7. [最佳实践](#最佳实践)

---

## MCP 简介

### 什么是 MCP (Model Context Protocol)

MCP (Model Context Protocol) 是一个开放协议，用于在 AI 助手和外部工具/服务之间建立标准化的通信接口。它允许 AI 助手（如 Claude、ChatGPT 等）动态调用外部工具来完成任务。

### MCP 的核心概念

1. **Server (服务器)**: 提供 MCP 工具的服务端实现
2. **Client (客户端)**: AI 助手，通过 MCP 协议调用工具
3. **Tools (工具)**: 服务器提供的可调用功能
4. **Transport (传输层)**: 服务器和客户端之间的通信方式（stdio、HTTP 等）

### MCP 的优势

- **标准化**: 统一的协议，兼容多个 AI 助手
- **灵活性**: 可以动态添加/移除工具
- **类型安全**: 支持 JSON Schema 定义输入输出
- **易于集成**: 简单的配置即可使用

---

## 为什么需要 MCP

### 当前 JSAST 的局限性

1. **命令行工具**: 只能通过 CLI 使用，不适合 AI 助手直接调用
2. **输出格式**: 控制台输出，结构化程度低
3. **交互性**: 缺少实时交互能力
4. **集成难度**: AI 助手难以直接集成和解析结果

### MCP 带来的改进

1. **AI 友好**: AI 助手可以直接调用扫描工具
2. **结构化输出**: JSON 格式，易于解析和处理
3. **实时反馈**: 支持交互式扫描和分析
4. **灵活配置**: 可以动态指定规则和目标

### 使用场景示例

```
用户: 帮我检查这个项目有没有安全问题
AI: 我来使用 jsast 扫描一下...
    [调用 MCP 工具: scan_project]
    发现 3 个高危漏洞，建议立即修复...
```

---

## 架构设计

### 整体架构

```
┌─────────────────┐
│   AI Assistant  │
│  (Claude/GPT)   │
└────────┬────────┘
         │ MCP Protocol
         │ (JSON-RPC)
         ▼
┌─────────────────────────┐
│   MCP Server (JSAST)    │
│  ┌───────────────────┐  │
│  │   Tool Registry   │  │
│  │  - scan_project   │  │
│  │  - scan_file      │  │
│  │  - get_rules      │  │
│  └────────┬──────────┘  │
│           │              │
│  ┌────────▼──────────┐  │
│  │  JSAST Core       │  │
│  │  - Analyzer       │  │
│  │  - Rule Manager   │  │
│  │  - Parser         │  │
│  └───────────────────┘  │
└─────────────────────────┘
```

### 核心组件

#### 1. MCP Server
- 使用 `@modelcontextprotocol/sdk` 实现
- 提供 stdio 传输层
- 管理工具注册和调用

#### 2. Tools (工具)
- **scan_project**: 扫描整个项目
- **scan_file**: 扫描单个文件
- **scan_directory**: 扫描指定目录
- **get_rules**: 获取可用规则列表
- **get_rule_config**: 获取规则配置

#### 3. JSAST Core
- 复用现有的分析器、规则管理器等核心组件
- 保持与 CLI 版本的一致性

### 数据流

```
Request (AI) → MCP Server → Tool Handler → JSAST Core → File System
                                                    ↓
Response ← MCP Server ← Tool Handler ← JSAST Core ← Analysis Result
```

---

## 实现步骤

### 步骤 1: 创建 MCP 服务器项目结构

```
jsast/
├── mcp-server/
│   ├── package.json
│   ├── src/
│   │   └── index.ts
│   ├── dist/
│   └── tsconfig.json
```

### 步骤 2: 安装依赖

```bash
cd mcp-server
bun add @modelcontextprotocol/sdk
bun add -d @types/node typescript
```

### 步骤 3: 实现 MCP 服务器核心

#### 3.1 初始化服务器

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'

const server = new Server(
  {
    name: 'jsast-mcp-server',
    version: '1.0.0'
  },
  {
    capabilities: {
      tools: {}
    }
  }
)

const transport = new StdioServerTransport()
await server.connect(transport)
```

#### 3.2 注册工具处理器

```typescript
// 列出可用工具
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'scan_project',
        description: 'Scan a JavaScript/TypeScript project',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: { type: 'string' },
            rulesPath: { type: 'string' }
          },
          required: ['projectPath']
        }
      }
      // ... 其他工具
    ]
  }
})

// 处理工具调用
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params

  switch (name) {
    case 'scan_project':
      return await scanProject(args)
    case 'scan_file':
      return await scanFile(args)
    // ... 其他工具
  }
})
```

### 步骤 4: 集成 JSAST 核心功能

```typescript
import { StaticAnalyzer } from '../src/core'
import { RuleManager } from '../src/rules'
import { processRules } from '../src/parse'
import { processFiles } from '../src/parse'

async function scanProject(args: any) {
  // 1. 加载规则
  const rules = loadRules(args.rulesPath, args.projectPath)
  const ruleManager = new RuleManager()
  ruleManager.registerRules(rules)

  // 2. 创建分析器
  const analyzer = new StaticAnalyzer(ruleManager.getAllRules())

  // 3. 获取文件列表
  const files = await processFiles({ projectPath: args.projectPath })

  // 4. 执行分析
  const results = await analyzer.analyzeFiles(files)

  // 5. 格式化结果
  return formatResults(results.flat())
}
```

### 步骤 5: 定义工具输入输出

#### 5.1 输入 Schema (JSON Schema)

```typescript
{
  type: 'object',
  properties: {
    projectPath: {
      type: 'string',
      description: 'Path to the project directory'
    },
    rulesPath: {
      type: 'string',
      description: 'Optional path to rules config'
    },
    filePattern: {
      type: 'string',
      description: 'Glob pattern to filter files'
    }
  },
  required: ['projectPath']
}
```

#### 5.2 输出格式

```typescript
{
  target: '/path/to/project',
  summary: {
    total: 10,
    high: 3,
    medium: 5,
    low: 2
  },
  issuesByFile: {
    '/path/to/file1.js': [
      {
        rule: 'no-command-injection',
        message: '不安全的命令执行',
        line: 10,
        column: 5,
        severity: 'high'
      }
    ]
  },
  allIssues: [...]
}
```

### 步骤 6: 错误处理

```typescript
try {
  const result = await handleToolCall(name, args)
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(result, null, 2)
      }
    ]
  }
} catch (error) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          error: error.message
        }, null, 2)
      }
    ],
    isError: true
  }
}
```

---

## 配置和使用

### 1. 构建 MCP 服务器

```bash
cd mcp-server
bun run build
```

### 2. 配置 Claude Desktop

在 Claude Desktop 的配置文件中添加：

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "jsast": {
      "command": "node",
      "args": [
        "C:\\develop\\code\\personal\\jsast\\mcp-server\\dist\\index.js"
      ],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

### 3. 使用示例

#### 示例 1: 扫描整个项目

```
用户: 帮我检查 src 目录的安全问题
AI: 我来扫描一下 src 目录...
    [调用 scan_project]
    扫描完成！发现 5 个问题：
    - 2 个高危：命令注入风险
    - 2 个中危：使用了 var 关键字
    - 1 个低危：使用了 console.log
```

#### 示例 2: 扫描单个文件

```
用户: 检查 utils.js 有没有安全问题
AI: 我来扫描 utils.js...
    [调用 scan_file]
    发现 1 个高危问题：第 15 行存在命令注入风险
```

#### 示例 3: 查看可用规则

```
用户: 有哪些安全规则可以使用？
AI: [调用 get_rules]
    当前可用 3 个规则：
    1. no-command-injection (高危) - 防止命令行注入
    2. no-var (中危) - 禁止使用 var
    3. no-console-log (低危) - 禁止使用 console.log
```

---

## 示例

### 完整的 MCP 服务器实现示例

```typescript
// mcp-server/src/index.ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js'
import { StaticAnalyzer } from '../src/core'
import { RuleManager } from '../src/rules'
import { processRules, processFiles } from '../src/parse'

class JsastMcpServer {
  private server: Server

  constructor() {
    this.server = new Server({
      name: 'jsast-mcp-server',
      version: '1.0.0'
    }, {
      capabilities: { tools: {} }
    })

    this.setupHandlers()
  }

  private setupHandlers() {
    // 列出工具
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'scan_project',
          description: 'Scan a project for security issues',
          inputSchema: {
            type: 'object',
            properties: {
              projectPath: { type: 'string' },
              rulesPath: { type: 'string' }
            },
            required: ['projectPath']
          }
        }
      ]
    }))

    // 处理工具调用
    this.server.setRequestHandler(CallToolRequestSchema, async (req) => {
      const { name, arguments: args } = req.params

      try {
        const result = await this.handleToolCall(name, args)
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        }
      } catch (error) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: error.message })
          }],
          isError: true
        }
      }
    })
  }

  private async handleToolCall(name: string, args: any) {
    switch (name) {
      case 'scan_project':
        return await this.scanProject(args)
      default:
        throw new Error(`Unknown tool: ${name}`)
    }
  }

  private async scanProject(args: any) {
    const { projectPath, rulesPath } = args

    // 加载规则
    const rules = this.loadRules(rulesPath, projectPath)
    const ruleManager = new RuleManager()
    ruleManager.registerRules(rules)

    // 创建分析器
    const analyzer = new StaticAnalyzer(ruleManager.getAllRules())

    // 获取文件
    const files = await processFiles({ projectPath })

    // 执行分析
    const results = await analyzer.analyzeFiles(files)

    return this.formatResults(results.flat())
  }

  private loadRules(rulesPath: string | undefined, projectPath: string) {
    // 实现规则加载逻辑
    return []
  }

  private formatResults(issues: any[]) {
    return {
      total: issues.length,
      issues
    }
  }

  async start() {
    const transport = new StdioServerTransport()
    await this.server.connect(transport)
  }
}

const server = new JsastMcpServer()
await server.start()
```

---

## 最佳实践

### 1. 错误处理

- 提供清晰的错误信息
- 区分不同类型的错误（文件不存在、权限问题等）
- 使用 try-catch 包裹所有可能失败的操作

### 2. 性能优化

- 缓存规则配置
- 并行处理多个文件
- 限制扫描的文件数量

### 3. 安全性

- 验证输入路径，防止路径遍历攻击
- 限制扫描范围
- 不暴露敏感信息

### 4. 可维护性

- 保持工具定义清晰
- 使用 TypeScript 类型
- 编写单元测试

### 5. 用户体验

- 提供详细的描述信息
- 返回结构化的结果
- 支持进度反馈（如果可能）

---

## 扩展建议

### 1. 添加更多工具

- `fix_issues`: 自动修复某些问题
- `generate_report`: 生成详细报告（HTML、PDF）
- `compare_scans`: 比较两次扫描结果

### 2. 支持更多传输方式

- HTTP 传输（用于 Web 应用）
- WebSocket 传输（实时更新）

### 3. 增强功能

- 实时进度反馈
- 增量扫描（只扫描修改的文件）
- 规则建议（根据项目特点推荐规则）

### 4. 集成 CI/CD

- GitHub Action
- GitLab CI
- Jenkins 插件

---

## 总结

MCP 服务器为 JSAST 提供了与 AI 助手集成的能力，使得：

1. **AI 助手可以直接调用**：无需手动运行命令
2. **结果结构化**：易于 AI 理解和处理
3. **交互式体验**：支持实时对话和分析
4. **易于扩展**：可以添加更多工具和功能

通过实现 MCP 服务器，JSAST 将成为一个更强大、更易用的安全分析工具。
