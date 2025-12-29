import type { ReportIssue } from '../type'
import chalk from 'chalk'

/**
 * 控制台报告生成器
 */
export class ConsoleReporter {
  /**
   * 生成控制台报告
   * @param issues 检查出的问题列表
   */
  generateReport(issues: ReportIssue[]): void {
    if (issues.length === 0) {
      console.log(chalk.green('✅ No issues found'))
      return
    }

    console.log(chalk.red('❌ Issues found:'))
    console.log(chalk.gray('='.repeat(60)))

    // Group issues by file
    const issuesByFile = issues.reduce((acc, issue) => {
      if (!acc[issue.filename]) {
        acc[issue.filename] = []
      }
      acc[issue.filename]!.push(issue)
      return acc
    }, {} as Record<string, ReportIssue[]>)

    // Output report
    for (const [filename, fileIssues] of Object.entries(issuesByFile)) {
      console.log(`\n📁 ${chalk.cyan('File:')} ${chalk.underline(filename)}`)
      console.log(chalk.gray('-'.repeat(60)))

      for (const issue of fileIssues) {
        const icon = issue.severity === 'high' ? '💥' : issue.severity === 'medium' ? '⚠️' : 'ℹ️'
        const severityColor = issue.severity === 'high' ? chalk.red : issue.severity === 'medium' ? chalk.yellow : chalk.blue
        console.log(`  ${severityColor(`${icon} [${issue.rule}] ${issue.message}`)}`)
        console.log(`     ${chalk.gray('Location:')} ${chalk.underline(`Line ${issue.line}, Column ${issue.column}`)}`)
        console.log(`     ${chalk.gray('File:')} ${chalk.underline(`${filename}:${issue.line}:${issue.column}`)}`)
      }
    }

    console.log('\n' + chalk.gray('='.repeat(60)))
    console.log(chalk.bold(`Total: ${issues.length} issues found`))
  }
}
