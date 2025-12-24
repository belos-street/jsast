import type { ReportIssue } from './type'
import * as fs from 'fs/promises'

/**
 * SARIF报告生成器
 */
export class SarifGenerator {
  /**
   * 生成SARIF格式报告
   * @param issues 检查出的问题列表
   * @returns SARIF格式的报告对象
   */
  generateSarifReport(issues: ReportIssue[]): any {
    // SARIF v2.1.0格式
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'JS/TS Static Analyzer',
              fullName: '基于Bun和Babel的JS/TS静态分析工具',
              version: '1.0.0',
              informationUri: 'https://github.com/user/jsast',
              rules: this.extractRulesFromIssues(issues)
            }
          },
          results: this.convertIssuesToSarifResults(issues),
          columnKind: 'utf16CodeUnits'
        }
      ]
    }
  }

  /**
   * 从问题列表中提取规则信息
   * @param issues 问题列表
   * @returns 规则列表
   */
  private extractRulesFromIssues(issues: ReportIssue[]): any[] {
    const ruleNames = new Set<string>()
    issues.forEach((issue) => ruleNames.add(issue.rule))

    return Array.from(ruleNames).map((ruleName) => ({
      id: ruleName,
      name: ruleName,
      shortDescription: {
        text: this.getRuleDescription(ruleName)
      },
      helpUri: `https://example.com/rules/${ruleName}`,
      properties: {
        severity: 'warning'
      }
    }))
  }

  /**
   * 获取规则描述
   * @param ruleName 规则名称
   * @returns 规则描述
   */
  private getRuleDescription(ruleName: string): string {
    const descriptions: Record<string, string> = {
      'no-var': '禁止使用var关键字',
      'no-console-log': '禁止使用console.log',
      'no-command-injection': '防止命令行注入攻击'
    }
    return descriptions[ruleName] || ruleName
  }

  /**
   * 将问题列表转换为SARIF结果格式
   * @param issues 问题列表
   * @returns SARIF结果列表
   */
  private convertIssuesToSarifResults(issues: ReportIssue[]): any[] {
    return issues.map((issue, index) => ({
      ruleId: issue.rule,
      message: {
        text: issue.message
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: issue.filename
            },
            region: {
              startLine: issue.line,
              startColumn: issue.column,
              endLine: issue.line,
              endColumn: issue.column
            }
          }
        }
      ],
      level: 'warning',
      codeFlows: [],
      relatedLocations: [],
      properties: {
        issueIndex: index
      }
    }))
  }

  /**
   * 生成并保存SARIF格式报告到文件
   * @param issues 问题列表
   * @param outputPath 输出文件路径
   */
  async saveSarifReport(issues: ReportIssue[], outputPath: string = 'sarif.json'): Promise<void> {
    const sarifReport = this.generateSarifReport(issues)
    await fs.writeFile(outputPath, JSON.stringify(sarifReport, null, 2), 'utf-8')
    console.log(`✅ SARIF报告已保存到: ${outputPath}`)
  }
}
