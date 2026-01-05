import { noConsoleLogRule } from './console-log'
import { varRule } from './no-var'
import { commandInjectionRule } from './command-injection'

export const ruleSet = [noConsoleLogRule, varRule, commandInjectionRule]
