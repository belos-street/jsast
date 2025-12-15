// 导出核心类和函数
import { StaticAnalyzer } from './src/analyzer'
import { parseCode } from './src/parser'
import { traverseAndCheck } from './src/traverser'

export {
  // 核心类
  StaticAnalyzer,

  // 工具函数
  parseCode,
  traverseAndCheck
}
