import type { ReportIssue } from './type'
import type { Rule } from '../rules'
import { ConsoleReporter } from './src/reporter'
import { SarifReporter } from './src/sarif-reporter'
import type { Arguments } from '@/cli'
import { basename, join } from 'path'

export interface ReportOptions {
  console?: boolean
  cliArgs?: Required<Arguments>
}

export class ReportManager {
  private consoleReporter: ConsoleReporter
  private sarifReporter: SarifReporter

  constructor() {
    this.consoleReporter = new ConsoleReporter()
    this.sarifReporter = new SarifReporter()
  }

  generateReports(issues: ReportIssue[], rules: Rule[], options: ReportOptions): void {
    const { console: enableConsole = true, cliArgs } = options

    if (enableConsole) {
      this.generateConsoleReport(issues)
    }

    if (cliArgs?.output) {
      this.generateSarifReport(issues, rules, cliArgs)
    }
  }

  private generateConsoleReport(issues: ReportIssue[]): void {
    this.consoleReporter.generateReport(issues)
  }

  private generateSarifReport(issues: ReportIssue[], rules: Rule[], cliArgs: Required<Arguments>): void {
    const { output, project } = cliArgs
    const projectName = basename(project) || 'unknown-project'
    const resolvedPath = join(output, `${projectName}-sarif.json`)
    this.sarifReporter.writeReport(issues, rules, resolvedPath)
    console.log(`\nSARIF report generated at: ${resolvedPath}`)
  }
}
