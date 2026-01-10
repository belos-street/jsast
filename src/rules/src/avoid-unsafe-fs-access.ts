import type { Rule } from '..'
import type { RuleIssue } from '../type'

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
