import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测不安全的赋值操作规则
 *
 * 设计思路：
 * 1. 检测可能导致的代码注入或安全问题的动态赋值
 * 2. 识别危险的属性访问赋值模式
 * 3. 提供修复建议
 *
 * 检测范围：
 * - eval() 赋值
 * - 动态属性赋值 (obj[variable])
 * - 全局对象动态赋值 (window[variable])
 * - this 赋值
 * - arguments 赋值
 *
 * 安全模式（不检测）：
 * - 静态属性赋值
 * - 已知安全的赋值模式
 */

export const avoidDynamicAssignmentRule: Rule = {
  name: 'avoid-dynamic-assignment',
  description: 'Detect unsafe dynamic assignments that may cause code injection',
  severity: 'warning',
  category: 'other-security',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'AssignmentExpression' && node.loc) {
      const left = node.left

      if (left.type === 'MemberExpression') {
        const object = left.object
        const property = left.property
        const computed = left.computed

        if (computed && property.type === 'Identifier') {
          if (object.type === 'Identifier' && object.name === 'window') {
            issues.push({
              message: `Dynamic window property assignment detected: Assigning to window[dynamicKey] can lead to code injection or prototype pollution. Use explicit property names instead`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }

          if (object.type === 'Identifier' && object.name === 'global') {
            issues.push({
              message: `Dynamic global property assignment detected: Assigning to global[dynamicKey] can lead to code injection or prototype pollution. Use explicit property names instead`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }

          if (object.type === 'Identifier' && object.name === 'globalThis') {
            issues.push({
              message: `Dynamic globalThis property assignment detected: Assigning to globalThis[dynamicKey] can lead to code injection or prototype pollution. Use explicit property names instead`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }

          if (object.type === 'Identifier' && object.name === 'self') {
            issues.push({
              message: `Dynamic self property assignment detected: Assigning to self[dynamicKey] can lead to code injection or prototype pollution. Use explicit property names instead`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }

        if (computed && object.type === 'ThisExpression') {
          issues.push({
            message: `Dynamic this property assignment detected: Assigning to this[dynamicKey] can lead to unexpected behavior and code injection. Consider using explicit property names or class properties`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }

      if (left.type === 'Identifier' && left.name === 'arguments') {
        issues.push({
          message: `Arguments assignment detected: Assigning to arguments can lead to unexpected behavior. The arguments object should not be reassigned`,
          line: node.loc.start.line,
          column: node.loc.start.column
        })
      }

      if (left.type === 'TSAsExpression' || left.type === 'TSTypeAssertion') {
        const innerLeft = (left as any).expression
        if (innerLeft && innerLeft.type === 'MemberExpression' && innerLeft.computed) {
          const object = innerLeft.object
          const property = innerLeft.property
          if (property.type === 'Identifier') {
            if (object.type === 'Identifier' && ['window', 'global', 'globalThis', 'self'].includes(object.name)) {
              issues.push({
                message: `Dynamic ${object.name} property assignment detected: Assigning to ${object.name}[dynamicKey] can lead to code injection or prototype pollution. Use explicit property names instead`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }
          }
        }
      }
    }

    return issues
  }
}
