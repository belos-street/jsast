import { noConsoleLogRule } from './console-log'
import { varRule } from './no-var'
import { commandInjectionRule } from './command-injection'
import { unsafeSpawnRule } from './unsafe-spawn'
import { noUnsafeShellRule } from './no-unsafe-shell'
import { detectSqlInjectionRule } from './detect-sql-injection'
import { avoidRawSqlRule } from './avoid-raw-sql'
import { detectMongoDbInjectionRule } from './detect-mongodb-injection'
import { avoidDangerouslySetInnerHtmlRule } from './avoid-dangerously-set-innerhtml'
import { avoidUnsafeHtmlRule } from './avoid-unsafe-html'
import { noEvalRule } from './no-eval'
import { noDocumentWriteRule } from './no-document-write'
import { detectPathTraversalRule } from './detect-path-traversal'
import { avoidUnsafeFsAccessRule } from './avoid-unsafe-fs-access'
import { validateJsonParseRule } from './validate-json-parse'
import { detectPrototypePollutionRule } from './detect-prototype-pollution'
import { useSecureRandomRule } from './use-secure-random'
import { avoidWeakCryptoRule } from './avoid-weak-crypto'
import { detectHardcodedSecretsRule } from './detect-hardcoded-secrets'
import { detectHardcodedUrlsRule } from './detect-hardcoded-urls'
import { useHttpsRule } from './use-https'
import { avoidSslVerificationDisabledRule } from './avoid-ssl-verification-disabled'
import { validateRedirectRule } from './validate-redirect'
import { hashPasswordsRule } from './hash-passwords'
import { enforceStrongPasswordRule } from './enforce-strong-password'
import { regenerateSessionRule } from './regenerate-session'

export const ruleSet = [
  noConsoleLogRule,
  varRule,
  commandInjectionRule,
  unsafeSpawnRule,
  noUnsafeShellRule,
  detectSqlInjectionRule,
  avoidRawSqlRule,
  detectMongoDbInjectionRule,
  avoidDangerouslySetInnerHtmlRule,
  avoidUnsafeHtmlRule,
  noEvalRule,
  noDocumentWriteRule,
  detectPathTraversalRule,
  avoidUnsafeFsAccessRule,
  validateJsonParseRule,
  detectPrototypePollutionRule,
  useSecureRandomRule,
  avoidWeakCryptoRule,
  detectHardcodedSecretsRule,
  detectHardcodedUrlsRule,
  useHttpsRule,
  avoidSslVerificationDisabledRule,
  validateRedirectRule,
  hashPasswordsRule,
  enforceStrongPasswordRule,
  regenerateSessionRule
]
