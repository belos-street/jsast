# jsast

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bun](https://img.shields.io/badge/Bun-1.0+-red.svg)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

A powerful static code analysis tool built with Bun and Babel, designed to detect potential security vulnerabilities and code quality issues in JavaScript/TypeScript projects.

## Features

- **Security Analysis**: Detects command injection, SQL injection, XSS, prototype pollution, and other critical vulnerabilities
- **Code Quality**: Enforces best practices like avoiding `eval()`, `var`, and weak cryptography
- **Modern Stack**: Built with Bun for fast performance and Babel for accurate AST analysis
- **Extensible**: Easy to add custom rules via a simple Rule interface
- **TypeScript Support**: Full type safety and IntelliSense support

## Tech Stack

- **Bun**: Fast JavaScript runtime and package manager
- **Babel**: AST parsing and traversal (`@babel/parser`, `@babel/traverse`, `@babel/types`)
- **TypeScript**: Type-safe codebase
- **ESLint**: Code linting with custom security rules

## Available Rules

### 1. Command Injection (命令注入)

| Rule | Severity | Description |
|------|----------|-------------|
| `command-injection` | Error | Detects command injection vulnerabilities |
| `unsafe-spawn` | Error | Detects unsafe spawn function calls |
| `no-unsafe-shell` | Error | Detects shell option misuse |

### 2. SQL Injection (SQL注入)

| Rule | Severity | Description |
|------|----------|-------------|
| `detect-sql-injection` | Error | Detects SQL injection vulnerabilities |
| `avoid-raw-sql` | Warning | Avoids raw SQL strings |
| `detect-mongodb-injection` | Error | Detects MongoDB injection vulnerabilities |

### 3. XSS (跨站脚本攻击)

| Rule | Severity | Description |
|------|----------|-------------|
| `no-eval` | Error | Disallows use of `eval()`, `setTimeout`, `setInterval` with strings |
| `no-document-write` | Error | Avoids document.write with untrusted input |
| `avoid-unsafe-html` | Error | Avoids generating HTML with untrusted input |
| `avoid-dangerously-set-innerhtml` | Error | Avoids innerHTML with untrusted input |

### 4. Path Traversal (路径遍历)

| Rule | Severity | Description |
|------|----------|-------------|
| `detect-path-traversal` | Error | Detects path traversal vulnerabilities |
| `avoid-unsafe-fs-access` | Error | Avoids unsafe filesystem access |

### 5. Insecure Deserialization (不安全的反序列化)

| Rule | Severity | Description |
|------|----------|-------------|
| `validate-json-parse` | Warning | Ensures JSON.parse input is validated |
| `detect-prototype-pollution` | Error | Detects prototype pollution vulnerabilities |
| `prevent-prototype-pollution` | Error | Prevents prototype pollution attacks |

### 6. Insecure Randomness (不安全的随机数)

| Rule | Severity | Description |
|------|----------|-------------|
| `use-secure-random` | Warning | Use secure random number generation |
| `avoid-weak-crypto` | Error | Avoids weak cryptographic algorithms |

### 7. Hardcoded Secrets (硬编码敏感信息)

| Rule | Severity | Description |
|------|----------|-------------|
| `detect-hardcoded-secrets` | Error | Detects hardcoded secrets and API keys |
| `detect-hardcoded-urls` | Warning | Detects hardcoded URLs and endpoints |

### 8. Insecure HTTP Requests (不安全的HTTP请求)

| Rule | Severity | Description |
|------|----------|-------------|
| `use-https` | Warning | Detects usage of HTTP instead of HTTPS |
| `avoid-ssl-verification-disabled` | Error | Detects disabled SSL verification |
| `validate-redirect` | Warning | Detects unsafe redirect patterns |

### 9. Insecure Authentication (不安全的认证和授权)

| Rule | Severity | Description |
|------|----------|-------------|
| `hash-passwords` | Error | Detects plaintext password storage |
| `enforce-strong-password` | Warning | Detects weak password policies |
| `regenerate-session` | Warning | Detects session fixation risks |

### 10. Code Quality (代码质量)

| Rule | Severity | Description |
|------|----------|-------------|
| `no-var` | Warning | Disallows `var` keyword, prefers `const`/`let` |
| `no-console-log` | Warning | Disallows `console.log` in production code |
| `no-debugger` | Warning | Disallows `debugger` statements |
| `no-alert` | Warning | Disallows `alert`, `confirm`, `prompt` calls |
| `handle-errors` | Warning | Disallows empty catch blocks |
| `avoid-duplicate-imports` | Warning | Detects duplicate imports |

### 11. Other Security Rules (其他安全规则)

| Rule | Severity | Description |
|------|----------|-------------|
| `validate-regexp` | Warning | Detects unsafe regular expressions (ReDoS) |
| `avoid-dynamic-assignment` | Warning | Detects unsafe dynamic assignments |

## Installation

```bash
bun install
```

## Quick Start

### Analyze a Single File

```bash
bun run src/main.ts <file-path>
```

Example:
```bash
bun run src/main.ts ./src/example.js
```

### Analyze a Directory

```bash
bun run src/main.ts <directory-path>
```

Example:
```bash
bun run src/main.ts ./src
```

### Analyze with Custom Rules

```bash
bun run src/main.ts --rules <rule1,rule2> <path>
```

Example:
```bash
bun run src/main.ts --rules command-injection,no-eval ./src
```

### Build Binary

Build the tool as a standalone binary for distribution:

```bash
bun run build:binary
```

This generates a `bin/jsast` executable that can be run without Bun:

```bash
# Linux/macOS
./bin/jsast ./src

# Windows
.\bin\jsast.exe ./src
```

## Configuration

Create a `.jsastrc.json` file in your project root:

```json
{
  "rules": ["command-injection", "no-eval", "detect-sql-injection"],
  "exclude": ["node_modules/", "dist/"],
  "severity": {
    "error": true,
    "warning": true
  }
}
```

## Report Formats

### Console Reporter (Default)

The default output format displays issues directly in the terminal with color-coded severity levels:

```
📁 File: ./src/example.js
------------------------------------------------------------
  💥 [command-injection] Potential command injection detected
     Location: Line 5, Column 10
     File: ./src/example.js:5:10

Total: 1 issues found
```

### SARIF Reporter

Generate SARIF (Static Analysis Results Interchange Format) reports for integration with CI/CD systems:

```bash
bun run src/main.ts --sarif ./report.json ./src
```

This generates a SARIF 2.1.0 compliant JSON report that can be uploaded to:
- GitHub Security tab
- Azure DevOps
- VS Code (with SARIF viewer extension)
- Other SARIF-compatible tools

## Development

### Running Tests

```bash
bun test
```

### Running Type Checking

```bash
bun run tsc
```

### Running Linter

```bash
bun run lint
```

### Adding a New Rule

1. Create a new rule file in `src/rules/src/`:

```typescript
// src/rules/src/my-new-rule.ts
import type { Rule } from '..'
import type { RuleIssue } from '../type'

export const myNewRuleRule: Rule = {
  name: 'my-new-rule',
  description: 'Description of what this rule detects',
  severity: 'warning',
  category: 'my-category',
  check(node) {
    const issues: RuleIssue[] = []
    // Implement rule logic here
    return issues
  }
}
```

2. Register the rule in `src/rules/src/index.ts`:

```typescript
import { myNewRuleRule } from './my-new-rule'

export const ruleSet = [
  // ... existing rules
  myNewRuleRule
]
```

3. Add the rule name to `src/rules/type.ts`:

```typescript
export type RuleName =
  | 'my-new-rule'
  // ... existing rule names
```

4. Write tests in `src/__test__/src/my-new-rule.test.ts`

## Project Structure

```
jsast/
├── src/
│   ├── main.ts                # CLI entry point
│   ├── cli/                   # CLI command handlers
│   ├── config/                # Configuration management
│   ├── core/                  # Core analysis engine
│   ├── parse/                  # File parsing and rule processing
│   ├── report/                 # Report generation
│   ├── rules/                  # Security and quality rules
│   │   └── src/                # Individual rule implementations
│   ├── utils/                  # Utility functions
│   └── __test__/               # Unit tests
├── package.json
├── tsconfig.json
└── README.md
```

## License

MIT