import type { Node, StringLiteral } from '@babel/types'
import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测重复的导入规则
 *
 * 设计思路：
 * 1. 收集所有导入语句
 * 2. 按模块路径分组
 * 3. 检测同一模块的重复导入
 * 4. 建议合并导入语句
 *
 * 检测范围：
 * - 同一模块的多个命名导入
 * - 同一模块的默认导入和命名导入
 * - 同一模块的多个默认导入
 *
 * 安全模式（不检测）：
 * - 不同模块的导入
 * - 类型导入（import type）
 */

interface ImportInfo {
  source: string
  specifiers: Array<{
    type: 'default' | 'namespace' | 'named'
    name: string
    line: number
    column: number
  }>
  line: number
  column: number
  isTypeImport: boolean
}

function getSourceValue(source: StringLiteral): string {
  return source.value
}

export const avoidDuplicateImportsRule: Rule = {
  name: 'avoid-duplicate-imports',
  description: 'Detect duplicate imports from the same module',
  severity: 'warning',
  category: 'code-quality',
  check(root) {
    const issues: RuleIssue[] = []
    const importsByModule: Map<string, ImportInfo[]> = new Map()

    function collectImports(node: Node) {
      if (node.type === 'ImportDeclaration' && node.source) {
        const source = getSourceValue(node.source)
        const isTypeImport = node.importKind === 'type'

        const specifiers: ImportInfo['specifiers'] = []

        if (node.specifiers) {
          for (const spec of node.specifiers) {
            if (spec.type === 'ImportDefaultSpecifier' && spec.local) {
              specifiers.push({
                type: 'default',
                name: spec.local.name,
                line: spec.loc?.start.line || 0,
                column: spec.loc?.start.column || 0
              })
            } else if (spec.type === 'ImportNamespaceSpecifier' && spec.local) {
              specifiers.push({
                type: 'namespace',
                name: spec.local.name,
                line: spec.loc?.start.line || 0,
                column: spec.loc?.start.column || 0
              })
            } else if (spec.type === 'ImportSpecifier' && spec.local) {
              specifiers.push({
                type: 'named',
                name: spec.local.name,
                line: spec.loc?.start.line || 0,
                column: spec.loc?.start.column || 0
              })
            }
          }
        }

        const importInfo: ImportInfo = {
          source,
          specifiers,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
          isTypeImport
        }

        const existing = importsByModule.get(source) || []
        existing.push(importInfo)
        importsByModule.set(source, existing)
      }

      for (const key of Object.keys(node)) {
        const child = (node as any)[key]
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            for (const item of child) {
              if (item && typeof item === 'object' && item.type) {
                collectImports(item)
              }
            }
          } else if (child.type) {
            collectImports(child)
          }
        }
      }
    }

    collectImports(root)

    for (const [source, imports] of importsByModule) {
      const regularImports = imports.filter((i) => !i.isTypeImport)
      const typeImports = imports.filter((i) => i.isTypeImport)

      if (regularImports.length > 1) {
        const lines = regularImports.map((i) => i.line).join(', ')
        issues.push({
          message: `Duplicate imports found: Module '${source}' is imported multiple times (lines: ${lines}). Consider merging imports into a single import statement`,
          line: regularImports[0]!.line,
          column: regularImports[0]!.column
        })
      }

      if (typeImports.length > 1) {
        const lines = typeImports.map((i) => i.line).join(', ')
        issues.push({
          message: `Duplicate type imports found: Module '${source}' is imported multiple times for types (lines: ${lines}). Consider merging imports into a single import statement`,
          line: typeImports[0]!.line,
          column: typeImports[0]!.column
        })
      }
    }

    return issues
  }
}
