#!/usr/bin/env bun

import { createCommand } from './cli'
import { processRules, processFiles } from './parse'

import { RuleManager } from './rules'

const bootstrap = async () => {
  const { options } = createCommand(process)

  const rules = processRules(options)

  const ruleManager = new RuleManager()
  ruleManager.registerRules(rules)
  console.log('处理后的规则:', ruleManager.getAllRules())

  const files = await processFiles({ projectPath: options.project })
  console.log('要检测的文件:', files)
}

bootstrap()
