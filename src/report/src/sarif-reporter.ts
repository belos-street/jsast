import type { ReportIssue, SarifReport, SarifRun, SarifTool, SarifDriver, SarifRule, SarifResult, SarifLocation } from '../type'
import type { Rule } from '../../rules'
import { writeFileSync } from 'fs'
import { dirname } from 'path'
import { mkdirSync } from 'fs'

export class SarifReporter {
  generateSarifReport(issues: ReportIssue[], rules: Rule[]): SarifReport {
    const ruleMap = new Map<string, Rule>(rules.map((rule) => [rule.name, rule]))

    const sarifRules: SarifRule[] = rules.map((rule) => {
      return {
        id: rule.name,
        name: rule.name,
        shortDescription: {
          text: rule.description
        },
        fullDescription: {
          text: rule.description
        },
        defaultConfiguration: {
          level: rule.severity
        }
      }
    })

    const results: SarifResult[] = issues.map((issue) => {
      const rule = ruleMap.get(issue.rule)
      const level = rule ? rule.severity : 'warning'

      const location: SarifLocation = {
        physicalLocation: {
          artifactLocation: {
            uri: issue.filename
          },
          region: {
            startLine: issue.line,
            startColumn: issue.column,
            endLine: issue.line,
            endColumn: issue.column + 1
          }
        }
      }

      return {
        ruleId: issue.rule,
        level,
        message: {
          text: issue.message
        },
        locations: [location]
      }
    })

    return this.buildSarifReport(sarifRules, results)
  }

  private buildSarifReport(sarifRules: SarifRule[], results: SarifResult[]): SarifReport {
    const driver: SarifDriver = {
      name: 'jsast',
      version: '1.0.0',
      informationUri: 'https://github.com/belos-street/jsast',
      rules: sarifRules
    }

    const tool: SarifTool = {
      driver
    }

    const run: SarifRun = {
      tool,
      results
    }

    return {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [run]
    }
  }

  writeReport(issues: ReportIssue[], rules: Rule[], outputPath: string): void {
    const sarifReport = this.generateSarifReport(issues, rules)
    const sarifJson = JSON.stringify(sarifReport, null, 2)

    const dir = dirname(outputPath)
    mkdirSync(dir, { recursive: true })

    writeFileSync(outputPath, sarifJson, 'utf-8')
  }
}
