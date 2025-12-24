import type { Arguments } from '@/cli'
import { readFileSync } from 'fs'
import type { RuleName } from '@/rules'

export enum RuleStatus {
  Disable = 0,
  Enable = 1
}

export type RuleConfig = {
  rules: Record<RuleName, RuleStatus>
}

export const processRules = (args: Required<Arguments>): RuleName[] => {
  const content = readFileSync(args.rules, 'utf-8')
  let config: RuleConfig

  try {
    config = JSON.parse(content) as RuleConfig
  } catch {
    throw new Error(`Invalid JSON file: ${args.rules}`)
  }

  // Validate rules field existence
  if (!config.rules || typeof config.rules !== 'object') {
    throw new Error(`Missing or invalid 'rules' field in: ${args.rules}`)
  }

  // Filter enabled rules (value 1)
  const rules: RuleName[] = []
  Object.entries(config.rules).forEach(([ruleName, value]) => {
    if (value === RuleStatus.Enable) {
      rules.push(ruleName as RuleName)
    }
  })

  return rules
}
