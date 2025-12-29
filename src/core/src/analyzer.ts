import type { Rule } from '@/rules'
import { parseCode } from './parser'
import { traverseAndCheck } from './traverser'
import type { ReportIssue } from '@/report'
import { file } from 'bun'

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

  /**
   * 分析单个文件路径
   * @param filePath 文件路径
   * @returns 检查出的问题列表
   */
  async analyzeFilePath(filePath: string): Promise<ReportIssue[]> {
    const content = await file(filePath).text()
    return this.analyzeFile(filePath, content)
  }

  /**
   * 批量分析多个文件
   * @param filePaths 文件路径列表
   * @returns 每个文件的问题列表
   */
  async analyzeFiles(filePaths: string[]): Promise<ReportIssue[][]> {
    return Promise.all(filePaths.map((filePath) => this.analyzeFilePath(filePath)))
  }
}
