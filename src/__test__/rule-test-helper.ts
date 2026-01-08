import { RuleManager, type RuleName } from '../rules'
import { StaticAnalyzer } from '../core'

export class RuleTestHelper {
  private ruleManager: RuleManager
  private analyzer: StaticAnalyzer

  constructor(registerBuiltIn: boolean = false) {
    this.ruleManager = new RuleManager()
    if (registerBuiltIn) {
      this.ruleManager.registerBuiltInRules()
    }
    this.analyzer = new StaticAnalyzer(this.ruleManager.getAllRules())
  }

  clearRules(): void {
    this.ruleManager = new RuleManager()
    this.analyzer = new StaticAnalyzer(this.ruleManager.getAllRules())
  }

  registerRule(ruleName: RuleName): void {
    this.ruleManager.registerRules([ruleName])
    this.analyzer = new StaticAnalyzer(this.ruleManager.getAllRules())
  }

  registerRules(ruleNames: RuleName[]): void {
    this.ruleManager.registerRules(ruleNames)
    this.analyzer = new StaticAnalyzer(this.ruleManager.getAllRules())
  }

  getAnalyzer(): StaticAnalyzer {
    return this.analyzer
  }

  getRuleManager(): RuleManager {
    return this.ruleManager
  }
}
