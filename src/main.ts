#!/usr/bin/env bun

import { createCommand } from './cli'
import { processRules } from './parse'

import { RuleManager } from './rules'

const bootstrap = async () => {
  const { options } = createCommand(process)

  const rules = processRules(options)
  const ruleManager = new RuleManager()
  ruleManager.registerRules(rules)

  console.log('处理后的规则:', ruleManager.getAllRules())
}

bootstrap()
