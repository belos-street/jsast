import type { ReportIssue } from './type'

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
      console.log('✅ 未发现任何问题')
      return
    }

    console.log('❌ 发现问题：')
    console.log('='.repeat(60))

    // 按文件分组
    const issuesByFile = issues.reduce((acc, issue) => {
      if (!acc[issue.filename]) {
        acc[issue.filename] = []
      }
      acc[issue.filename]!.push(issue)
      return acc
    }, {} as Record<string, ReportIssue[]>)

    // 输出报告
    for (const [filename, fileIssues] of Object.entries(issuesByFile)) {
      console.log(`\n📁 文件: ${filename}`)
      console.log('-'.repeat(60))

      for (const issue of fileIssues) {
        console.log(`  🚨 [${issue.rule}] ${issue.message}`)
        console.log(`     位置: 第 ${issue.line} 行, 第 ${issue.column} 列`)
      }
    }

    console.log('\n' + '='.repeat(60))
    console.log(`总计: ${issues.length} 个问题`)
  }
}
