// 文件验证工具
export { validateDirectory, validateFile, validateFileExtension, validateOutputDirectory } from './src/file-validator'

export type { ValidationResult } from './type'

// 路径工具
export { normalizeToAbsolutePath, validateAbsolutePath, getPathDisplayName } from './src/path-utils'
