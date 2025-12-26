import { validateAbsolutePath, normalizeToAbsolutePath } from '@/utils'
import { existsSync } from 'fs'
import { resolve } from 'path'

import { type Arguments } from '../type'
import { FILE_NAME } from '@/config'

export const validateArguments = (args: Arguments): Required<Arguments> => {
  // Validate project path
  if (!existsSync(args.project)) {
    console.error(`Error: Project path does not exist: ${args.project}`)
    process.exit(1)
  }

  // Handle output path
  let outputPath: string
  if (args.output) {
    if (!validateAbsolutePath(args.output)) {
      outputPath = normalizeToAbsolutePath(args.output)
    } else {
      outputPath = args.output
    }
  } else {
    // Default output to project root directory
    outputPath = args.project
  }

  // Handle rules path
  let rulesPath: string | undefined
  if (args.rules) {
    // Use rules file specified in command line
    if (!validateAbsolutePath(args.rules)) {
      rulesPath = normalizeToAbsolutePath(args.rules)
    } else {
      rulesPath = args.rules
    }

    if (!existsSync(rulesPath)) {
      console.error(`Error: Rules file does not exist: ${rulesPath}`)
      rulesPath = undefined
    }
  } else {
    // Try to read default config file in project root
    const defaultConfigPath = resolve(args.project, FILE_NAME.config)
    if (existsSync(defaultConfigPath)) {
      rulesPath = defaultConfigPath
    } else {
      console.error(`Error: No rules file specified and ${FILE_NAME.config} not found in project root`)
      rulesPath = undefined
    }
  }

  if (!rulesPath) {
    process.exit(1)
  }

  return {
    project: args.project,
    output: outputPath,
    rules: rulesPath
  }
}
