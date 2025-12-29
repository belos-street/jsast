#!/usr/bin/env bun

import { createCommand } from './cli'
import { processRules, processFiles } from './parse'
import { RuleManager } from './rules'
import { StaticAnalyzer } from './core'
import { ConsoleReporter } from './report'

const bootstrap = async () => {
  //1. 解析命令行参数
  const { options } = createCommand(process)

  //2. 处理规则参数
  const rules = processRules(options)
  const ruleManager = new RuleManager()
  ruleManager.registerRules(rules)

  //3. 处理项目路径参数
  const files = await processFiles({ projectPath: options.project })

  //4. 分析文件
  const analyzer = new StaticAnalyzer(ruleManager.getAllRules())
  const results = await analyzer.analyzeFiles(files)

  // Flatten results
  const allIssues = results.flat()

  // Generate report
  const reporter = new ConsoleReporter()
  reporter.generateReport(allIssues)
}

bootstrap()
