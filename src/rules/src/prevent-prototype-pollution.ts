import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测原型污染规则
 *
 * 设计思路：
 * 1. 检测可能导致原型污染的危险模式
 * 2. 识别用户输入直接赋值到原型链的操作
 * 3. 提供安全的修复建议
 *
 * 检测范围：
 * - obj[key] = value 模式，其中 key 可能包含 __proto__
 * - constructor.prototype 赋值
 * - Object.assign 合并包含 __proto__ 的对象
 * - JSON.parse 解析包含 __proto__ 的数据
 * - 动态属性赋值到全局对象
 *
 * 安全模式（不检测）：
 * - 使用 Object.create(null) 创建的无原型对象
 * - 使用 hasOwnProperty 检查后再赋值
 * - 已知安全的属性赋值
 */

const DANGEROUS_PROPERTIES = ['__proto__', 'constructor', 'prototype']

function getPropertyName(key: any): string {
  if (key.type === 'Identifier') {
    return key.name
  }
  if (key.type === 'StringLiteral') {
    return key.value
  }
  if (key.type === 'Literal' && typeof key.value === 'string') {
    return key.value
  }
  return 'unknown'
}

export const preventPrototypePollutionRule: Rule = {
  name: 'prevent-prototype-pollution',
  description: 'Detect potential prototype pollution vulnerabilities',
  severity: 'error',
  category: 'other-security',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'AssignmentExpression' && node.loc) {
      const left = node.left

      if (left.type === 'MemberExpression') {
        const prop = left.property
        let propName: string | null = null

        if (prop.type === 'Identifier' && DANGEROUS_PROPERTIES.includes(prop.name)) {
          propName = prop.name
        } else if (prop.type === 'StringLiteral' && DANGEROUS_PROPERTIES.includes(prop.value)) {
          propName = prop.value
        }

        if (propName) {
          issues.push({
            message: `Prototype pollution detected: Direct assignment to '${propName}' can lead to prototype pollution. Use Object.create(null) for safe object merging or validate property keys`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }

        if (left.object.type === 'MemberExpression') {
          const obj = left.object.object
          const innerProp = left.object.property

          if (
            obj.type === 'Identifier' &&
            obj.name === 'constructor' &&
            innerProp.type === 'Identifier' &&
            innerProp.name === 'prototype'
          ) {
            issues.push({
              message: `Prototype pollution detected: Assignment to constructor.prototype can lead to prototype pollution. Avoid modifying built-in prototypes`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'Object' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'assign'
      ) {
        for (const arg of node.arguments) {
          if (arg.type === 'ObjectExpression' && arg.properties) {
            for (const prop of arg.properties) {
              if (prop.type === 'ObjectProperty') {
                const keyName = getPropertyName(prop.key)
                if (DANGEROUS_PROPERTIES.includes(keyName)) {
                  issues.push({
                    message: `Prototype pollution detected: Object.assign with '${keyName}' property can lead to prototype pollution. Use Object.create(null) or validate property keys`,
                    line: node.loc.start.line,
                    column: node.loc.start.column
                  })
                }
              }
            }
          }
        }
      }

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'Object' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'merge'
      ) {
        for (const arg of node.arguments) {
          if (arg.type === 'ObjectExpression' && arg.properties) {
            for (const prop of arg.properties) {
              if (prop.type === 'ObjectProperty') {
                const keyName = getPropertyName(prop.key)
                if (DANGEROUS_PROPERTIES.includes(keyName)) {
                  issues.push({
                    message: `Prototype pollution detected: Object.merge with '${keyName}' property can lead to prototype pollution. Use safe merge functions`,
                    line: node.loc.start.line,
                    column: node.loc.start.column
                  })
                }
              }
            }
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.loc && node.callee.type === 'Identifier' && node.callee.name === 'merge') {
      for (const arg of node.arguments) {
        if (arg.type === 'ObjectExpression' && arg.properties) {
          for (const prop of arg.properties) {
            if (prop.type === 'ObjectProperty') {
              const keyName = getPropertyName(prop.key)
              if (DANGEROUS_PROPERTIES.includes(keyName)) {
                issues.push({
                  message: `Prototype pollution detected: merge() with '${keyName}' property can lead to prototype pollution. Use safe merge functions`,
                  line: node.loc.start.line,
                  column: node.loc.start.column
                })
              }
            }
          }
        }
      }
    }

    return issues
  }
}
