import type { Node } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 会话固定风险检测规则
 *
 * 设计思路：
 * 1. 检测登录成功后未重新生成session ID
 * 2. 识别常见的登录函数和认证流程
 * 3. 检测session相关操作
 * 4. 建议在登录后重新生成session
 *
 * 检测范围：
 * - 登录成功后未调用session regenerate
 * - 认证成功后未更新session ID
 * - 使用固定session ID进行认证
 *
 * 安全模式（不检测）：
 * - 已调用session regenerate
 * - 使用passport.js等认证库的自动session管理
 * - 使用JWT等无状态认证
 */

const LOGIN_FUNCTIONS = ['login', 'authenticate', 'signIn', 'signin', 'logIn', 'auth', 'authenticateUser', 'userLogin']

const SESSION_REGENERATE_FUNCTIONS = ['regenerate', 'regenerateId', 'save', 'reload', 'touch']

const SESSION_VARIABLES = ['session', 'req.session', 'request.session', 'ctx.session']

function isLoginFunction(node: Node): boolean {
  if (node.type === 'Identifier' && LOGIN_FUNCTIONS.includes(node.name)) {
    return true
  }
  if (node.type === 'MemberExpression') {
    const property = node.property
    if (property.type === 'Identifier' && LOGIN_FUNCTIONS.includes(property.name)) {
      return true
    }
  }
  return false
}

function isSessionRegenerateCall(node: Node): boolean {
  if (node.type === 'ExpressionStatement') {
    return isSessionRegenerateCall(node.expression)
  }
  if (node.type === 'CallExpression') {
    const callee = node.callee
    if (callee.type === 'MemberExpression') {
      const object = callee.object
      const property = callee.property
      if (property.type === 'Identifier' && SESSION_REGENERATE_FUNCTIONS.includes(property.name)) {
        if (object.type === 'Identifier' && SESSION_VARIABLES.includes(object.name)) {
          return true
        }
        if (object.type === 'MemberExpression') {
          const objProperty = object.property
          if (objProperty.type === 'Identifier' && objProperty.name === 'session') {
            return true
          }
        }
      }
    }
  }
  return false
}

function isLoginSuccessBlock(node: Node): boolean {
  if (node.type === 'IfStatement') {
    const test = node.test
    if (test.type === 'CallExpression' && isLoginFunction(test.callee)) {
      return true
    }
    if (test.type === 'Identifier' && test.name === 'authenticated') {
      return true
    }
    if (test.type === 'Identifier' && test.name === 'success') {
      return true
    }
  }
  return false
}

function hasSessionRegenerateInBlock(node: Node): boolean {
  if (!node) return false

  if (node.type === 'BlockStatement') {
    for (const stmt of node.body) {
      if (isSessionRegenerateCall(stmt)) {
        return true
      }
      if (stmt.type === 'IfStatement' && hasSessionRegenerateInBlock(stmt.consequent)) {
        return true
      }
      if (stmt.type === 'IfStatement' && stmt.alternate && hasSessionRegenerateInBlock(stmt.alternate)) {
        return true
      }
    }
  }
  return false
}

export const regenerateSessionRule: Rule = {
  name: 'regenerate-session',
  description: 'Detect session fixation risk',
  severity: 'warning',
  category: 'insecure-authentication',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'IfStatement' && node.loc) {
      if (isLoginSuccessBlock(node)) {
        const hasRegenerate = hasSessionRegenerateInBlock(node.consequent)
        if (!hasRegenerate) {
          issues.push({
            message: `Session fixation risk: Login success detected but session ID is not regenerated. Regenerate the session ID after successful authentication to prevent session fixation attacks. Use session.regenerate() or equivalent method`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    return issues
  }
}
