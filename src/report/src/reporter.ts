import type { ReportIssue } from '../type'

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
      console.log('✅ No issues found')
      return
    }

    console.log('❌ Issues found:')
    console.log('='.repeat(60))

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
      console.log(`\n📁 File: ${filename}`)
      console.log('-'.repeat(60))

      for (const issue of fileIssues) {
        const icon = issue.severity === 'high' ? '💥' : issue.severity === 'medium' ? '⚠️' : 'ℹ️'
        console.log(`  ${icon} [${issue.rule}] ${issue.message}`)
        console.log(`     Location: Line ${issue.line}, Column ${issue.column}`)
      }
    }

    console.log('\n' + '='.repeat(60))
    console.log(`Total: ${issues.length} issues found`)
  }
}
