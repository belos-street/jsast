import type { Rule, RuleName } from './type'
import { ruleSet } from './src'
/**
 * 规则管理器类
 */
export class RuleManager {
  private ruleRegistry = new Map<RuleName, Rule>()

  constructor() {}

  /**
   * 注册内置规则
   */
  registerBuiltInRules(): void {
    ruleSet.forEach((rule) => this.registerRule(rule))
  }

  /**
   * 注册单个规则
   * @param rule 要注册的规则
   */
  registerRule(rule: Rule): void {
    this.ruleRegistry.set(rule.name, rule)
  }

  /**
   * 获取单个规则
   * @param name 规则名称
   * @returns 规则对象，如果不存在则返回undefined
   */
  getRule(name: RuleName): Rule | undefined {
    return this.ruleRegistry.get(name)
  }

  /**
   * 获取所有规则
   * @returns 所有规则的数组
   */
  getAllRules(): Rule[] {
    return Array.from(this.ruleRegistry.values())
  }

  /**
   * 根据规则名称列表注册规则
   * @param ruleNames 规则名称列表
   */
  registerRules(ruleNames: RuleName[]): void {
    ruleNames.forEach((ruleName) => {
      const rule = ruleSet.find((r) => r.name === ruleName)
      if (rule) this.registerRule(rule)
    })
  }

  /**
   * 根据规则名称列表获取规则
   * @param ruleNames 规则名称列表
   * @returns 对应的规则数组
   */
  getRulesByName(ruleNames: RuleName[]): Rule[] {
    return ruleNames.map((name) => this.getRule(name)).filter((rule) => rule !== undefined) as Rule[]
  }
}
