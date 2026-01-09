import { noConsoleLogRule } from './console-log'
import { varRule } from './no-var'
import { commandInjectionRule } from './command-injection'
import { unsafeSpawnRule } from './unsafe-spawn'
import { noUnsafeShellRule } from './no-unsafe-shell'
import { detectSqlInjectionRule } from './detect-sql-injection'
import { avoidRawSqlRule } from './avoid-raw-sql'
import { detectMongoDbInjectionRule } from './detect-mongodb-injection'
import { noEvalRule } from './no-eval'

export const ruleSet = [
  noConsoleLogRule,
  varRule,
  commandInjectionRule,
  unsafeSpawnRule,
  noUnsafeShellRule,
  detectSqlInjectionRule,
  avoidRawSqlRule,
  detectMongoDbInjectionRule,
  noEvalRule
]
