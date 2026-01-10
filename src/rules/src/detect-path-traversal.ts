import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 路径遍历检测规则
 *
 * 设计思路：
 * 1. 检测文件系统操作中的动态路径拼接，包括模板字符串和字符串拼接
 * 2. 支持多种文件系统方法：readFile, readFileSync, writeFile, writeFileSync, unlink, unlinkSync, existsSync, stat, readdir, mkdir, rmdir, appendFile, appendFileSync, rename, copyFile, access
 * 3. 识别不同的调用模式：直接调用、require模式、类实例化
 * 4. 忽略安全的静态路径字符串
 *
 * 检测范围：
 * - 模板字符串中的动态内容：`fs.readFile(\`./data/${userInput}\`)`
 * - 字符串拼接：`fs.readFileSync('./data/' + userInput)`
 * - 各种文件系统方法的使用模式
 *
 * 安全模式（不检测）：
 * - 静态路径字符串：`fs.readFile('./data/config.json')`
 * - 不在检测列表中的方法：`fs.createReadStream('./data/config.json')`
 */
export const detectPathTraversalRule: Rule = {
  name: 'detect-path-traversal',
  description: 'Detects path traversal vulnerabilities',
  severity: 'error',
  category: 'path-traversal',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee

      const fsMethods = [
        'readFile',
        'readFileSync',
        'writeFile',
        'writeFileSync',
        'unlink',
        'unlinkSync',
        'existsSync',
        'stat',
        'statSync',
        'readdir',
        'readdirSync',
        'mkdir',
        'mkdirSync',
        'rmdir',
        'rmdirSync',
        'appendFile',
        'appendFileSync',
        'rename',
        'renameSync',
        'copyFile',
        'copyFileSync',
        'access',
        'accessSync',
        'lstat',
        'lstatSync',
        'realpath',
        'realpathSync',
        'readlink',
        'readlinkSync',
        'chmod',
        'chmodSync',
        'chown',
        'chownSync',
        'utimes',
        'utimesSync',
        'open',
        'openSync',
        'close',
        'closeSync',
        'read',
        'readSync',
        'write',
        'writeSync'
      ]

      const checkPathTraversal = (methodName: string, libraryName?: string, checkAllArgs = false) => {
        const argsToCheck = checkAllArgs ? node.arguments : [node.arguments[0]]

        for (const arg of argsToCheck) {
          if (arg && (arg.type === 'TemplateLiteral' || arg.type === 'BinaryExpression')) {
            const libPrefix = libraryName ? `${libraryName}.` : ''
            issues.push({
              message: `Path traversal vulnerability: ${libPrefix}${methodName} uses dynamically concatenated path, vulnerable to path traversal`,
              line: node.loc!.start.line,
              column: node.loc!.start.column
            })
          }
        }
      }

      if (callee.type === 'MemberExpression') {
        const property = callee.property

        if (property.type === 'Identifier' && fsMethods.includes(property.name)) {
          const object = callee.object

          if (object.type === 'Identifier') {
            const objectName = object.name

            if (objectName === 'fs') {
              const checkAllArgs = ['rename', 'renameSync', 'copyFile', 'copyFileSync'].includes(property.name)
              checkPathTraversal(property.name, objectName, checkAllArgs)
            } else if (objectName === 'path') {
              const checkAllArgs = ['rename', 'renameSync', 'copyFile', 'copyFileSync'].includes(property.name)
              checkPathTraversal(property.name, objectName, checkAllArgs)
            }
          }

          if (object.type === 'NewExpression' && object.callee.type === 'Identifier') {
            const className = object.callee.name

            if (className === 'FileHandle' && ['read', 'write', 'close', 'stat'].includes(property.name)) {
              checkPathTraversal(property.name, 'fs.FileHandle')
            }
          }

          if (object.type === 'CallExpression' && object.callee.type === 'Identifier' && object.callee.name === 'require') {
            const requireArg = object.arguments[0]
            if (requireArg && requireArg.type === 'StringLiteral') {
              const libName = requireArg.value

              if (libName === 'fs' && fsMethods.includes(property.name)) {
                const checkAllArgs = ['rename', 'renameSync', 'copyFile', 'copyFileSync'].includes(property.name)
                const argsToCheck = checkAllArgs ? node.arguments : [node.arguments[0]]

                for (const arg of argsToCheck) {
                  if (arg && (arg.type === 'TemplateLiteral' || arg.type === 'BinaryExpression')) {
                    issues.push({
                      message: `Path traversal vulnerability: require('fs').${property.name} uses dynamically concatenated path, vulnerable to path traversal`,
                      line: node.loc!.start.line,
                      column: node.loc!.start.column
                    })
                  }
                }
              }
            }
          }
        }
      }

      if (callee.type === 'Identifier' && fsMethods.includes(callee.name)) {
        const firstArg = node.arguments[0]
        if (firstArg && (firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
          issues.push({
            message: `Path traversal vulnerability: ${callee.name} uses dynamically concatenated path, vulnerable to path traversal`,
            line: node.loc.start.line,
            column: node.loc.start.column
          })
        }
      }
    }

    return issues
  }
}
