import { parse } from '@babel/parser'
import traverse from '@babel/traverse'
import type { File, Node } from '@babel/types'

// 配置类型定义
interface Rule {
  name: string
  description: string
  check: (node: Node, filename: string) => ReportIssue[]
}

interface ReportIssue {
  rule: string
  message: string
  line: number
  column: number
  filename: string
}

// 示例规则：禁止使用console.log
const noConsoleLogRule: Rule = {
  name: 'no-console-log',
  description: '禁止使用console.log',
  check(node: Node, filename: string): ReportIssue[] {
    const issues: ReportIssue[] = []
    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === 'console' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'log' &&
      node.loc
    ) {
      issues.push({
        rule: 'no-console-log',
        message: '禁止使用console.log',
        line: node.loc.start.line,
        column: node.loc.start.column,
        filename
      })
    }
    return issues
  }
}

// 示例规则：禁止使用var
const varRule: Rule = {
  name: 'no-var',
  description: '禁止使用var关键字',
  check(node: Node, filename: string): ReportIssue[] {
    const issues: ReportIssue[] = []
    if (node.type === 'VariableDeclaration' && node.kind === 'var' && node.loc) {
      issues.push({
        rule: 'no-var',
        message: '禁止使用var关键字，请使用let或const',
        line: node.loc.start.line,
        column: node.loc.start.column,
        filename
      })
    }
    return issues
  }
}

// 安全规则：检测命令行注入风险
const commandInjectionRule: Rule = {
  name: 'no-command-injection',
  description: '检测命令行注入风险',
  check(node: Node, filename: string): ReportIssue[] {
    const issues: ReportIssue[] = []

    // 检测不安全的child_process函数调用
    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      // 检查直接调用child_process.exec/execSync/spawnSync等
      if (callee.type === 'MemberExpression') {
        // 检测形式：child_process.exec('...')
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'child_process' &&
          callee.property.type === 'Identifier' &&
          ['exec', 'execSync', 'execFile', 'execFileSync'].includes(callee.property.name)
        ) {
          const firstArg = node.arguments[0]
          // 检查第一个参数是否是模板字符串或二元表达式（拼接）
          if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
            issues.push({
              rule: 'no-command-injection',
              message: `不安全的命令执行：${callee.property.name} 使用了动态拼接的命令字符串，存在命令注入风险`,
              line: node.loc.start.line,
              column: node.loc.start.column,
              filename
            })
          }
        }

        // 检测形式：require('child_process').exec('...')
        if (
          callee.object.type === 'CallExpression' &&
          callee.object.callee.type === 'Identifier' &&
          callee.object.callee.name === 'require' &&
          callee.object.arguments.length > 0
        ) {
          const requireArg = callee.object.arguments[0]!
          if (
            requireArg.type === 'StringLiteral' &&
            requireArg.value === 'child_process' &&
            callee.property.type === 'Identifier' &&
            ['exec', 'execSync', 'execFile', 'execFileSync'].includes(callee.property.name)
          ) {
            const firstArg = node.arguments[0]
            if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
              issues.push({
                rule: 'no-command-injection',
                message: `不安全的命令执行：require('child_process').${callee.property.name} 使用了动态拼接的命令字符串，存在命令注入风险`,
                line: node.loc.start.line,
                column: node.loc.start.column,
                filename
              })
            }
          }
        }
      }

      // 检测形式：直接调用exec('...')（假设已导入）
      if (callee.type === 'Identifier' && ['exec', 'execSync'].includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
          issues.push({
            rule: 'no-command-injection',
            message: `不安全的命令执行：${callee.name} 使用了动态拼接的命令字符串，存在命令注入风险`,
            line: node.loc.start.line,
            column: node.loc.start.column,
            filename
          })
        }
      }
    }

    return issues
  }
}

// 静态分析器类
class StaticAnalyzer {
  private rules: Rule[]

  constructor(rules: Rule[]) {
    this.rules = rules
  }

  // 解析代码为AST
  private parseCode(code: string, filename: string): File | null {
    try {
      return parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx'],
        sourceFilename: filename
      })
    } catch (error) {
      console.error(`解析错误 ${filename}:`, error)
      return null
    }
  }

  // 分析单个文件
  analyzeFile(filename: string, code: string): ReportIssue[] {
    const ast = this.parseCode(code, filename)
    if (!ast) return []

    const issues: ReportIssue[] = []

    // 遍历AST并检查规则
    traverse(ast, {
      enter: (path) => {
        for (const rule of this.rules) {
          const ruleIssues = rule.check(path.node, filename)
          issues.push(...ruleIssues)
        }
      }
    })

    return issues
  }

  // 生成报告
  generateReport(issues: ReportIssue[]): void {
    if (issues.length === 0) {
      console.log('✅ 未发现任何问题')
      return
    }

    console.log('❌ 发现问题：')
    console.log('='.repeat(60))

    // 按文件分组
    const issuesByFile = issues.reduce((acc, issue) => {
      if (!acc[issue.filename]) {
        acc[issue.filename] = []
      }
      acc[issue.filename]!.push(issue)
      return acc
    }, {} as Record<string, ReportIssue[]>)

    // 输出报告
    for (const [filename, fileIssues] of Object.entries(issuesByFile)) {
      console.log(`\n📁 文件: ${filename}`)
      console.log('-'.repeat(60))

      for (const issue of fileIssues) {
        console.log(`  🚨 [${issue.rule}] ${issue.message}`)
        console.log(`     位置: 第 ${issue.line} 行, 第 ${issue.column} 列`)
      }
    }

    console.log('\n' + '='.repeat(60))
    console.log(`总计: ${issues.length} 个问题`)
  }
}

// 测试代码
const testCode = `
const a = 1;
var b = 2; // 应该触发no-var规则

console.log('Hello World'); // 应该触发no-console-log规则

function foo() {
  var c = 3; // 应该触发no-var规则
  console.log('foo'); // 应该触发no-console-log规则
}

// 命令行注入测试案例
const child_process = require('child_process');
const userInput = 'rm -rf /';

// 不安全的用法 - 应该触发规则
child_process.exec('ls -la ' + userInput);
child_process.execSync('ls -la ' + userInput);
require('child_process').execFile('echo ' + userInput);

// 安全的用法 - 不应该触发规则
child_process.exec('ls -la');
child_process.execSync('ls -la', { shell: false });
child_process.spawn('ls', ['-la']);
`

// 运行分析
const analyzer = new StaticAnalyzer([noConsoleLogRule, varRule, commandInjectionRule])
const issues = analyzer.analyzeFile('test.js', testCode)
analyzer.generateReport(issues)
