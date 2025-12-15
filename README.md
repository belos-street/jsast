# jsast

一个基于 Bun 和 Babel 的静态代码分析工具，类似 ESLint，用于检测 JavaScript/TypeScript 代码中的潜在问题。

## 功能特性

- **核心功能**：基于 Babel 的代码解析和 AST 遍历
- **规则检查**：自定义实现的规则检查系统
- **安全检测**：包含命令行注入等安全相关规则
- **报告生成**：清晰的问题报告输出
- **模块化设计**：便于扩展和维护

## 安装依赖

```bash
bun install
```

## 快速开始

### 分析单个文件

```bash
bun run src/main.ts <文件路径>
```

### 分析目录

```bash
bun run src/main.ts <目录路径>
```

## 项目结构

```
jsast/
├── src/
│   ├── core/             # 核心功能模块
│   │   ├── src/
│   │   │   ├── analyzer.ts   # 静态分析器主类
│   │   │   ├── parser.ts     # 代码解析模块
│   │   │   └── traverser.ts  # AST遍历模块
│   │   └── index.ts          # core模块入口
│   ├── rules/            # 规则定义
│   │   ├── no-console-log.ts     # 禁止使用console.log规则
│   │   ├── no-var.ts             # 禁止使用var规则
│   │   ├── no-command-injection.ts  # 命令行注入检测规则
│   │   └── index.ts              # 规则模块入口
│   ├── main.ts           # 项目入口文件
│   └── ...
├── package.json
├── tsconfig.json
└── README.md
```

## 技术栈

- **Bun**：JavaScript 运行时和包管理器
- **Babel**：代码解析和 AST 处理（@babel/parser, @babel/traverse, @babel/types）
- **TypeScript**：类型安全
- **Node.js API**：文件系统操作和命令行参数处理

## 可用规则

1. **no-console-log**：禁止使用 `console.log`
2. **no-var**：禁止使用 `var` 关键字
3. **no-command-injection**：检测命令行注入风险

## 开发

### 添加新规则

1. 在 `src/rules/` 目录下创建新的规则文件
2. 实现 `Rule` 接口
3. 在 `src/rules/index.ts` 中导出新规则

### 运行类型检查

```bash
bun tsc --noEmit
```

## License

MIT

