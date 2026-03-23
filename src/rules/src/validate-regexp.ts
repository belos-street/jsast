import type { Rule } from '..'
import type { RuleIssue } from '../type'

/**
 * 检测不安全的正则表达式规则
 *
 * 设计思路：
 * 1. 检测可能导致 ReDoS 的正则表达式
 * 2. 识别危险的量词组合和嵌套模式
 * 3. 提供修复建议
 *
 * 检测范围：
 * - 嵌套量词 (如 (a+)+)
 * - 交替重叠 (如 (a|a)+)
 * - 回溯陷阱 (如 .*.*)
 * - 使用 new RegExp() 创建的动态正则表达式
 *
 * 安全模式（不检测）：
 * - 简单的正则表达式
 * - 无危险量词的正则表达式
 */

const DANGEROUS_PATTERNS = [
  {
    pattern: /\([^)]*\+[^)]*\)\+/,
    description: 'Nested quantifier',
    example: '(a+)+'
  },
  {
    pattern: /\([^)]*\*[^)]*\)\+/,
    description: 'Nested quantifier',
    example: '(a*)+'
  },
  {
    pattern: /\([^)]*\+[^)]*\)\*/,
    description: 'Nested quantifier',
    example: '(a+)*'
  },
  {
    pattern: /\([^)]*\*[^)]*\)\*/,
    description: 'Nested quantifier',
    example: '(a*)*'
  },
  {
    pattern: /\([^)]*\+[^)]*\)\{/,
    description: 'Nested quantifier with quantifier',
    example: '(a+){1,}'
  },
  {
    pattern: /\([^)]*\|[^)]*\)\+/,
    description: 'Alternation with quantifier',
    example: '(a|b)+'
  },
  {
    pattern: /\(\?:[^)]*\)\+/,
    description: 'Non-capturing group with quantifier',
    example: '(?:a+)+'
  },
  {
    pattern: /\.\+\.\+/,
    description: 'Overlapping wildcards',
    example: '.+.+'
  },
  {
    pattern: /\.\*\.\*/,
    description: 'Overlapping wildcards',
    example: '.*.*'
  },
  {
    pattern: /\.\+\.\*/,
    description: 'Overlapping wildcards',
    example: '.+.*'
  },
  {
    pattern: /\.\*\.\+/,
    description: 'Overlapping wildcards',
    example: '.*.+'
  },
  {
    pattern: /\([^)]*\?[^)]*\)\+/,
    description: 'Optional group with quantifier',
    example: '(a?)+'
  },
  {
    pattern: /\([^)]*\{[^}]*\}[^)]*\)\+/,
    description: 'Quantified group with quantifier',
    example: '(a{1,3})+'
  }
]

function checkRegexPattern(pattern: string): { isDangerous: boolean; description: string; example: string } {
  for (const dangerous of DANGEROUS_PATTERNS) {
    if (dangerous.pattern.test(pattern)) {
      return {
        isDangerous: true,
        description: dangerous.description,
        example: dangerous.example
      }
    }
  }
  return { isDangerous: false, description: '', example: '' }
}

export const validateRegexpRule: Rule = {
  name: 'validate-regexp',
  description: 'Detect unsafe regular expressions that may cause ReDoS',
  severity: 'warning',
  category: 'other-security',
  check(node) {
    const issues: RuleIssue[] = []

    if (node.type === 'RegExpLiteral' && node.loc) {
      const pattern = node.pattern || ''
      const flags = node.flags || ''

      const result = checkRegexPattern(pattern)
      if (result.isDangerous) {
        issues.push({
          message: `Unsafe regular expression detected: Pattern /${pattern}/${flags} contains ${result.description} (e.g., ${result.example}). This may cause catastrophic backtracking and ReDoS vulnerability. Consider using atomic groups, possessive quantifiers, or simplifying the pattern`,
          line: node.loc.start.line,
          column: node.loc.start.column
        })
      }
    }

    if (node.type === 'NewExpression' && node.loc) {
      const callee = node.callee
      if (callee.type === 'Identifier' && callee.name === 'RegExp') {
        const args = node.arguments
        if (args.length > 0 && args[0]) {
          const patternArg = args[0]
          if (patternArg.type === 'StringLiteral') {
            const pattern = patternArg.value
            const flags = args.length > 1 && args[1] && args[1].type === 'StringLiteral' ? args[1].value : ''

            const result = checkRegexPattern(pattern)
            if (result.isDangerous) {
              issues.push({
                message: `Unsafe regular expression detected: new RegExp("${pattern}"${flags ? `, "${flags}"` : ''}) contains ${result.description} (e.g., ${result.example}). This may cause catastrophic backtracking and ReDoS vulnerability. Consider using atomic groups, possessive quantifiers, or simplifying the pattern`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }
          } else {
            issues.push({
              message: `Dynamic regular expression detected: new RegExp() is called with a dynamic pattern. This may lead to ReDoS vulnerabilities if user input is used. Validate and sanitize the pattern before use`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.loc) {
      const callee = node.callee
      if (callee.type === 'Identifier' && callee.name === 'RegExp') {
        const args = node.arguments
        if (args.length > 0 && args[0]) {
          const patternArg = args[0]
          if (patternArg.type === 'StringLiteral') {
            const pattern = patternArg.value
            const flags = args.length > 1 && args[1] && args[1].type === 'StringLiteral' ? args[1].value : ''

            const result = checkRegexPattern(pattern)
            if (result.isDangerous) {
              issues.push({
                message: `Unsafe regular expression detected: RegExp("${pattern}"${flags ? `, "${flags}"` : ''}) contains ${result.description} (e.g., ${result.example}). This may cause catastrophic backtracking and ReDoS vulnerability. Consider using atomic groups, possessive quantifiers, or simplifying the pattern`,
                line: node.loc.start.line,
                column: node.loc.start.column
              })
            }
          } else {
            issues.push({
              message: `Dynamic regular expression detected: RegExp() is called with a dynamic pattern. This may lead to ReDoS vulnerabilities if user input is used. Validate and sanitize the pattern before use`,
              line: node.loc.start.line,
              column: node.loc.start.column
            })
          }
        }
      }
    }

    return issues
  }
}
