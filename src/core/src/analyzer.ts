import { parseCode } from './parser'
import { traverseAndCheck } from './traverser'
import type { Rule, ReportIssue } from './traverser'

/**
 * 静态分析器类
 */
export class StaticAnalyzer {
  private rules: Rule[]

  /**
   * 创建静态分析器实例
   * @param rules 要应用的规则列表
   */
  constructor(rules: Rule[]) {
    this.rules = rules
  }

  /**
   * 分析单个文件
   * @param filename 文件名
   * @param code 文件内容
   * @returns 检查出的问题列表
   */
  analyzeFile(filename: string, code: string): ReportIssue[] {
    const ast = parseCode(code, filename)
    if (!ast) return []

    return traverseAndCheck(ast, this.rules, filename)
  }
}
