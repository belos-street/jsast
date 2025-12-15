// 导出所有规则
import { noConsoleLogRule } from './src/no-console-log'
import { noVarRule } from './src/no-var'
import { noCommandInjectionRule } from './src/no-command-injection'

export type { Rule } from './type'

// 所有可用规则列表
export const rules = [noConsoleLogRule, noVarRule, noCommandInjectionRule]

// 单独导出每个规则，方便按需导入
export { noConsoleLogRule, noVarRule, noCommandInjectionRule }
