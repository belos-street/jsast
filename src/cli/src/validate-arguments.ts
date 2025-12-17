import { existsSync, statSync } from 'fs'
import { dirname } from 'path'
import { ValidationResult } from '@/utils'
import { normalizeToAbsolutePath, validateAbsolutePath } from '@/utils/src/path-utils'

// 命令行参数类型
export type CLIArguments = {
  project: string
  output: string
  rules: string
}

// 验证结果类型
export type ArgumentsValidationResult = {
  isValid: boolean
  errors: string[]
  normalizedArguments?: CLIArguments
}

/**
 * 验证project路径
 * @param projectPath - 项目路径
 * @returns 验证结果
 */
export const validateProjectPath = (projectPath: string): ValidationResult => {
  // 检查路径是否为绝对路径
  if (!validateAbsolutePath(projectPath)) {
    return {
      isValid: false,
      error: `项目路径必须是绝对路径：${projectPath}`
    }
  }

  // 检查路径是否存在
  if (!existsSync(projectPath)) {
    return {
      isValid: false,
      error: `项目路径不存在：${projectPath}`
    }
  }

  // 检查路径是否为目录
  const stat = statSync(projectPath)
  if (!stat.isDirectory()) {
    return {
      isValid: false,
      error: `项目路径必须是目录：${projectPath}`
    }
  }

  return { isValid: true }
}

/**
 * 验证所有命令行参数
 * @param rawArguments - 原始命令行参数
 * @returns 验证结果，包含错误信息和标准化后的参数
 */
export const validateArguments = (rawArguments: Record<string, string>): ArgumentsValidationResult => {
  const errors: string[] = []
  const { project, output, rules } = rawArguments

  // 验证project路径
  const projectValidation = validateProjectPath(project)
  if (!projectValidation.isValid) {
    errors.push(projectValidation.error!)
  }

  // 验证output路径
  const outputValidation = validateOutputPath(output)
  if (!outputValidation.isValid) {
    errors.push(outputValidation.error!)
  }

  // 验证rules路径
  const rulesValidation = validateRulesPath(rules)
  if (!rulesValidation.isValid) {
    errors.push(rulesValidation.error!)
  }

  if (errors.length > 0) {
    return {
      isValid: false,
      errors
    }
  }

  // 所有验证通过，返回标准化的参数
  return {
    isValid: true,
    errors: [],
    normalizedArguments: {
      project,
      output,
      rules
    }
  }
}

/**
 * 验证rules路径
 * @param rulesPath - 规则配置文件路径
 * @returns 验证结果
 */
export const validateRulesPath = (rulesPath: string): ValidationResult => {
  // 检查路径是否为绝对路径
  if (!validateAbsolutePath(rulesPath)) {
    return {
      isValid: false,
      error: `规则配置文件路径必须是绝对路径：${rulesPath}`
    }
  }

  // 检查文件是否存在
  if (!existsSync(rulesPath)) {
    return {
      isValid: false,
      error: `规则配置文件不存在：${rulesPath}`
    }
  }

  // 检查是否为文件
  const stat = statSync(rulesPath)
  if (!stat.isFile()) {
    return {
      isValid: false,
      error: `规则配置文件路径必须是文件：${rulesPath}`
    }
  }

  // 检查文件扩展名是否为.json
  if (!rulesPath.endsWith('.json')) {
    return {
      isValid: false,
      error: `规则配置文件必须是JSON格式：${rulesPath}`
    }
  }

  return { isValid: true }
}

/**
 * 验证output路径
 * @param outputPath - 输出路径
 * @returns 验证结果
 */
export const validateOutputPath = (outputPath: string): ValidationResult => {
  // 检查路径是否为绝对路径
  if (!validateAbsolutePath(outputPath)) {
    return {
      isValid: false,
      error: `输出路径必须是绝对路径：${outputPath}`
    }
  }

  // 获取输出路径的目录
  const outputDir = dirname(outputPath)

  // 检查输出目录是否存在
  if (!existsSync(outputDir)) {
    return {
      isValid: false,
      error: `输出路径的目录不存在：${outputDir}`
    }
  }

  // 检查输出目录是否为目录
  const stat = statSync(outputDir)
  if (!stat.isDirectory()) {
    return {
      isValid: false,
      error: `输出路径的父级必须是目录：${outputDir}`
    }
  }

  return { isValid: true }
}
