import type { Expression, Node } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测原型污染漏洞规则
 *
 * 设计思路：
 * 1. 检测直接的原型操作，包括 __proto__、constructor、prototype 属性的赋值
 * 2. 检测不安全的对象操作方法，如 Object.assign、Object.create、Object.defineProperty 等
 * 3. 检测常见的合并函数，如 lodash.merge、jQuery.extend，特别是与未受信任输入结合使用时
 * 4. 检测 spread operator 展开包含原型污染属性的对象
 * 5. 使用递归检查嵌套对象中的原型污染属性
 *
 * 检测范围：
 * - obj.__proto__ = value: 直接赋值 __proto__ 属性
 * - Object.prototype[key] = value: 动态赋值 Object.prototype
 * - obj.constructor.prototype[key] = value: 动态赋值 constructor.prototype
 * - Object.assign(target, { __proto__: malicious }): 使用 __proto__ 属性
 * - Object.assign(target, { [key]: value }): 使用计算属性
 * - Object.defineProperty(obj, "__proto__", { value: malicious }): 定义 __proto__ 属性
 * - Object.create({ __proto__: malicious }): 创建包含原型污染属性的对象
 * - Object.setPrototypeOf(obj, maliciousInput): 使用未受信任输入设置原型
 * - Reflect.defineProperty(obj, "__proto__", { value: malicious }): 定义 __proto__ 属性
 * - lodash.merge(target, userInput): 使用未受信任输入合并对象
 * - lodash.merge(target, { nested: { __proto__: malicious } }): 合并包含原型污染属性的对象
 * - jQuery.extend(target, userInput): 使用未受信任输入扩展对象
 * - { ...target, ...{ __proto__: malicious } }: 使用 spread operator 展开包含原型污染属性的对象
 *
 * 安全模式（不检测）：
 * - 静态字符串：Object.assign(target, { name: "test" })
 * - 安全标识符：Object.setPrototypeOf(obj, null)、Object.setPrototypeOf(obj, Object.prototype)
 * - 安全合并：lodash.merge(target, { name: "test" })
 * - 安全展开：{ ...target, ...{ name: "test" } }
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function hasPrototypePollution(obj: Record<string, any>): boolean {
  if (obj.type === 'ObjectExpression') {
    for (const prop of obj.properties) {
      if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
        const key = prop.key

        if (key.type === 'Identifier' && (key.name === '__proto__' || key.name === 'constructor' || key.name === 'prototype')) {
          return true
        }

        if (prop.value.type === 'ObjectExpression') {
          if (hasPrototypePollution(prop.value)) {
            return true
          }
        }
      }
    }
  }
  return false
}

function isSafeIdentifier(node: Node): boolean {
  if (node.type !== 'Identifier') {
    return false
  }

  const safeNames = ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'null']
  return safeNames.includes(node.name)
}

function isUntrustedInput(node: Node): boolean {
  if (node.type === 'Identifier') {
    const unsafeNames = ['userInput', 'input', 'data', 'params', 'query', 'body', 'req', 'request']
    return unsafeNames.includes(node.name)
  }
  return false
}

export const detectPrototypePollutionRule: Rule = {
  name: 'detect-prototype-pollution',
  description: 'Detects prototype pollution vulnerabilities',
  severity: 'error',
  category: 'insecure-deserialization',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'AssignmentExpression' && node.loc) {
      const left = node.left

      if (left.type === 'MemberExpression') {
        const object = left.object
        const property = left.property

        if (left.computed) {
          if (property.type === 'StringLiteral' && property.value === '__proto__') {
            issues.push({
              message: 'Prototype pollution: Direct assignment to __proto__ property, vulnerable to prototype pollution attacks',
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }

          if (property.type !== 'StringLiteral') {
            if (
              object.type === 'MemberExpression' &&
              object.object.type === 'Identifier' &&
              object.object.name === 'Object' &&
              object.property.type === 'Identifier' &&
              object.property.name === 'prototype'
            ) {
              issues.push({
                message:
                  'Prototype pollution: Direct assignment to Object.prototype with dynamic key, vulnerable to prototype pollution attacks',
                line: node.loc!.start.line,
                column: node.loc!.start.column
              })
            } else if (
              object.type === 'MemberExpression' &&
              object.object.type === 'Identifier' &&
              object.object.name === 'constructor' &&
              object.property.type === 'Identifier' &&
              object.property.name === 'prototype'
            ) {
              issues.push({
                message:
                  'Prototype pollution: Direct assignment to constructor.prototype with dynamic key, vulnerable to prototype pollution attacks',
                line: node.loc!.start.line,
                column: node.loc!.start.column
              })
            } else if (
              object.type === 'MemberExpression' &&
              object.property.type === 'Identifier' &&
              object.property.name === 'prototype'
            ) {
              issues.push({
                message:
                  'Prototype pollution: Direct assignment to prototype with dynamic key, vulnerable to prototype pollution attacks',
                line: node.loc!.start.line,
                column: node.loc!.start.column
              })
            }
          }
        } else {
          if (property.type === 'Identifier' && property.name === '__proto__') {
            issues.push({
              message: 'Prototype pollution: Direct assignment to __proto__ property, vulnerable to prototype pollution attacks',
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      if (callee.type === 'MemberExpression') {
        const object = callee.object
        const property = callee.property

        if (object.type === 'Identifier' && property.type === 'Identifier') {
          if (object.name === 'Object' && property.name === 'assign') {
            const args = node.arguments

            for (const arg of args) {
              if (arg.type === 'ObjectExpression') {
                let hasComputedProperty = false
                let hasProtoProperty = false

                for (const prop of arg.properties) {
                  if (prop.type === 'ObjectProperty') {
                    const key = prop.key

                    if (key.type === 'Identifier' && key.name === '__proto__') {
                      hasProtoProperty = true
                    }

                    if (prop.computed) {
                      hasComputedProperty = true
                    }
                  }
                }

                if (hasProtoProperty) {
                  issues.push({
                    message:
                      'Prototype pollution: Object.assign with __proto__ property, vulnerable to prototype pollution attacks',
                    line: node.loc!.start.line,
                    column: node.loc!.start.column
                  })
                }

                if (hasComputedProperty) {
                  issues.push({
                    message:
                      'Prototype pollution: Object.assign with computed property, vulnerable to prototype pollution attacks',
                    line: node.loc!.start.line,
                    column: node.loc!.start.column
                  })
                }
              }
            }
          }

          if (object.name === 'Object' && property.name === 'defineProperty') {
            const args = node.arguments

            if (args.length >= 2) {
              const secondArg = args[1] as Expression

              if (secondArg.type === 'StringLiteral' && secondArg.value === '__proto__') {
                issues.push({
                  message:
                    'Prototype pollution: Object.defineProperty with __proto__ property, vulnerable to prototype pollution attacks',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
                })
              }
            }
          }

          if (object.name === 'Object' && property.name === 'create') {
            const args = node.arguments

            if (args.length >= 1) {
              const firstArg = args[0] as Expression

              if (firstArg.type === 'ObjectExpression' && hasPrototypePollution(firstArg)) {
                issues.push({
                  message:
                    'Prototype pollution: Object.create with object containing prototype pollution properties, vulnerable to prototype pollution attacks',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
                })
              }
            }
          }

          if (object.name === 'Object' && property.name === 'setPrototypeOf') {
            const args = node.arguments

            if (args.length >= 2) {
              const secondArg = args[1] as Expression

              if (!isSafeIdentifier(secondArg) && secondArg.type !== 'NullLiteral') {
                issues.push({
                  message:
                    'Prototype pollution: Object.setPrototypeOf with untrusted input, vulnerable to prototype pollution attacks',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
                })
              }
            }
          }

          if (object.name === 'Reflect' && property.name === 'defineProperty') {
            const args = node.arguments

            if (args.length >= 2) {
              const secondArg = args[1] as Expression

              if (secondArg.type === 'StringLiteral' && secondArg.value === '__proto__') {
                issues.push({
                  message:
                    'Prototype pollution: Reflect.defineProperty with __proto__ property, vulnerable to prototype pollution attacks',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
                })
              }
            }
          }

          if ((object.name === 'lodash' || object.name === '_') && property.name === 'merge') {
            const args = node.arguments

            for (const arg of args) {
              if (arg.type === 'ObjectExpression') {
                if (hasPrototypePollution(arg)) {
                  issues.push({
                    message:
                      'Prototype pollution: lodash.merge with object containing prototype pollution properties, vulnerable to prototype pollution attacks',
                    line: node.loc!.start.line,
                    column: node.loc!.start.column
                  })
                }
              } else if (isUntrustedInput(arg)) {
                issues.push({
                  message: 'Prototype pollution: lodash.merge with untrusted input, vulnerable to prototype pollution attacks',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
                })
              }
            }
          }

          if ((object.name === 'jQuery' || object.name === '$') && property.name === 'extend') {
            const args = node.arguments

            for (const arg of args) {
              if (arg.type === 'ObjectExpression') {
                if (hasPrototypePollution(arg)) {
                  issues.push({
                    message:
                      'Prototype pollution: jQuery.extend with object containing prototype pollution properties, vulnerable to prototype pollution attacks',
                    line: node.loc!.start.line,
                    column: node.loc!.start.column
                  })
                }
              } else if (isUntrustedInput(arg)) {
                issues.push({
                  message: 'Prototype pollution: jQuery.extend with untrusted input, vulnerable to prototype pollution attacks',
                  line: node.loc!.start.line,
                  column: node.loc!.start.column
                })
              }
            }
          }
        }
      }
    }

    if (node.type === 'ObjectExpression' && node.loc) {
      for (const prop of node.properties) {
        if (prop.type === 'SpreadElement' && prop.argument.type === 'ObjectExpression') {
          if (hasPrototypePollution(prop.argument)) {
            issues.push({
              message:
                'Prototype pollution: Spread operator with object containing prototype pollution properties, vulnerable to prototype pollution attacks',
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }
        }
      }
    }

    return issues
  }
}
