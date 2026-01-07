import { noConsoleLogRule } from './console-log'
import { varRule } from './no-var'
import { commandInjectionRule } from './command-injection'
import { unsafeSpawnRule } from './unsafe-spawn'

export const ruleSet = [noConsoleLogRule, varRule, commandInjectionRule, unsafeSpawnRule]
