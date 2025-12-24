import { noConsoleLogRule } from './no-console-log'
import { noVarRule } from './no-var'
import { noCommandInjectionRule } from './no-command-injection'

export const ruleSet = [noConsoleLogRule, noVarRule, noCommandInjectionRule]
