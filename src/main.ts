#!/usr/bin/env bun

import { createCommand } from './cli'
import { processRules, processFiles } from './parse'
import { RuleManager } from './rules'
import { StaticAnalyzer } from './core'
import { ReportManager } from './report'

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
  const flatResults = results.flat()

  //5. 生成报告
  const reportManager = new ReportManager()
  reportManager.generateReports(flatResults, ruleManager.getAllRules(), {
    console: true,
    cliArgs: options
  })
}

bootstrap()
