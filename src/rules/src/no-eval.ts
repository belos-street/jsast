import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 禁止使用 eval、setTimeout 和 setInterval 的字符串参数规则
 *
 * 设计思路：
 * 1. 检测 eval 函数的直接调用，无论参数类型
 * 2. 检测 setTimeout 和 setInterval 的字符串参数调用
 * 3. 字符串参数包括 StringLiteral 和 TemplateLiteral
 *
 * 检测范围：
 * - eval(code): eval 函数调用
 * - setTimeout('alert(1)', 1000): setTimeout 字符串参数
 * - setInterval('console.log("test")', 1000): setInterval 字符串参数
 * - setTimeout(`alert(${userInput})`, 1000): setTimeout 模板字符串
 * - setInterval(`console.log(${data})`, 1000): setInterval 模板字符串
 *
 * 安全模式（不检测）：
 * - setTimeout(callback, 1000): 函数参数
 * - setInterval(callback, 1000): 函数参数
 * - setTimeout(() => {}, 1000): 箭头函数
 */
export const noEvalRule: Rule = {
  name: 'no-eval',
  description: 'Detects use of eval, setTimeout, and setInterval with string arguments',
  severity: 'error',
  category: 'xss',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'Identifier') {
        const functionName = callee.name

        if (functionName === 'eval') {
          issues.push({
            message: 'Avoid using eval: eval executes arbitrary code and can lead to code injection vulnerabilities',
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        } else if (functionName === 'setTimeout' || functionName === 'setInterval') {
          const firstArg = node.arguments[0]
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            issues.push({
              message: `Avoid using ${functionName} with string argument: ${functionName} with string argument executes arbitrary code and can lead to code injection vulnerabilities`,
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
