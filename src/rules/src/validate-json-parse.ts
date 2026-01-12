import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * JSON.parse 输入验证规则
 *
 * 设计思路：
 * 1. 检测 JSON.parse 调用中的第一个参数
 * 2. 判断参数是否为静态字符串字面量
 * 3. 非静态字符串参数视为未验证输入，需要报告问题
 *
 * 检测范围：
 * - JSON.parse(userInput): 变量参数
 * - JSON.parse(request.body): 对象属性
 * - JSON.parse(data): 函数调用结果
 * - JSON.parse('${userInput}'): 模板字符串
 * - JSON.parse('static' + userInput): 字符串拼接
 *
 * 安全模式（不检测）：
 * - 静态字符串：JSON.parse('{"key": "value"}')
 * - 字符串字面量：JSON.parse('[]')
 */
export const validateJsonParseRule: Rule = {
  name: 'validate-json-parse',
  description: 'Validate JSON.parse calls to ensure input is validated',
  severity: 'warning',
  category: 'insecure-deserialization',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'JSON' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'parse'
      ) {
        const firstArg = node.arguments[0]

        if (firstArg && firstArg.type !== 'StringLiteral') {
          issues.push({
            message:
              'Unsafe JSON.parse: JSON.parse uses unvalidated input, vulnerable to injection attacks. Use try-catch and validate input before parsing',
            line: node.loc!.start.line,
            column: node.loc!.start.column
          })
        }
      }
    }

    return issues
  }
}
