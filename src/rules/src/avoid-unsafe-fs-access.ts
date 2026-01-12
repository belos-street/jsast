import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 避免不安全的文件系统访问规则
 *
 * 设计思路：
 * 1. 检测 fs 模块的常见文件操作方法：readFile、writeFile、unlink、mkdir、rmdir、readdir、stat 等
 * 2. 检查路径参数是否为动态拼接（模板字符串或二元表达式）
 * 3. 对于需要检查多个路径参数的方法（如 rename、copyFile），检查所有相关参数
 * 4. 支持多种调用模式：直接调用、require 调用、变量引用
 *
 * 检测范围：
 * - fs.readFile(`./data/${userInput}.json`): 动态路径
 * - fs.writeFile('path/' + userInput + '/file.txt'): 字符串拼接
 * - fs.unlinkSync(`${dir}/${filename}`): 同步方法
 * - fs.rename(oldPath, newPath): 检查两个路径参数
 * - require('fs').readFile(`./data/${userInput}.json`): require 调用
 * - readFile(`./data/${userInput}.json`): 直接调用
 *
 * 安全模式（不检测）：
 * - 静态路径：fs.readFile('./data/config.json')
 * - 字符串字面量：fs.writeFile('/tmp/file.txt', 'content')
 */
export const avoidUnsafeFsAccessRule: Rule = {
  name: 'avoid-unsafe-fs-access',
  description: 'Avoid unsafe file system access with dynamically concatenated paths',
  severity: 'warning',
  category: 'path-traversal',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      const fsMethods = [
        'readFile',
        'writeFile',
        'unlink',
        'mkdir',
        'rmdir',
        'readdir',
        'stat',
        'existsSync',
        'appendFile',
        'rename',
        'copyFile',
        'readFileSync',
        'writeFileSync',
        'unlinkSync',
        'mkdirSync',
        'rmdirSync',
        'readdirSync',
        'statSync',
        'renameSync',
        'copyFileSync'
      ]

      const checkUnsafeFsAccess = (methodName: string, libraryName?: string, checkAllArgs = false) => {
        const argsToCheck = checkAllArgs ? node.arguments : [node.arguments[0]]

        for (const arg of argsToCheck) {
          if (arg && (arg.type === 'TemplateLiteral' || arg.type === 'BinaryExpression')) {
            const libPrefix = libraryName ? `${libraryName}.` : ''
            issues.push({
              message: `Unsafe file system access: ${libPrefix}${methodName} uses dynamically concatenated path, vulnerable to path traversal`,
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }
        }
      }

      if (callee.type === 'MemberExpression') {
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'fs' &&
          callee.property.type === 'Identifier' &&
          fsMethods.includes(callee.property.name)
        ) {
          const methodName = callee.property.name
          const checkAllArgs = ['rename', 'renameSync', 'copyFile', 'copyFileSync'].includes(methodName)
          checkUnsafeFsAccess(methodName, 'fs', checkAllArgs)
        }

        if (
          callee.object.type === 'CallExpression' &&
          callee.object.callee.type === 'Identifier' &&
          callee.object.callee.name === 'require' &&
          callee.object.arguments.length > 0
        ) {
          const requireArg = callee.object.arguments[0]
          if (
            requireArg &&
            requireArg.type === 'StringLiteral' &&
            requireArg.value === 'fs' &&
            callee.property.type === 'Identifier' &&
            fsMethods.includes(callee.property.name)
          ) {
            const methodName = callee.property.name
            const checkAllArgs = ['rename', 'renameSync', 'copyFile', 'copyFileSync'].includes(methodName)
            checkUnsafeFsAccess(methodName, "require('fs')", checkAllArgs)
          }
        }
      }

      if (callee.type === 'Identifier' && fsMethods.includes(callee.name)) {
        const methodName = callee.name
        const checkAllArgs = ['rename', 'renameSync', 'copyFile', 'copyFileSync'].includes(methodName)
        checkUnsafeFsAccess(methodName, undefined, checkAllArgs)
      }
    }

    return issues
  }
}
