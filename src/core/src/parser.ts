import { parse } from '@babel/parser'
import type { File } from '@babel/types'

/**
 * 解析代码为AST
 * @param code 要解析的代码字符串
 * @param filename 文件名（用于错误报告）
 * @returns 解析后的AST对象，如果解析失败则返回null
 */
export function parseCode(code: string, filename: string): File | null {
  try {
    return parse(code, {
      sourceType: 'module',
      plugins: ['typescript', 'jsx'],
      sourceFilename: filename
    })
  } catch (error) {
    console.error(`解析错误 ${filename}:`, error)
    return null
  }
}
