import { extname } from 'path'
import { glob } from 'glob'

export interface ProcessOptions {
  projectPath: string
  include?: string[] // 包含的文件路径模式
  exclude?: string[] // 排除的文件路径模式
  extensions?: string[] // 包含的文件扩展名
}

export const processFiles = async (options: ProcessOptions) => {
  // Default configuration
  const defaultExcludes = ['node_modules', '.git']
  const defaultExtensions = ['.js', '.ts', '.mjs', '.mts']

  // Merge options with defaults
  const excludes = [...defaultExcludes, ...(options.exclude || [])]
  const extensions = [...defaultExtensions, ...(options.extensions || [])]

  // Use glob pattern matching
  const files = await glob('**/*', {
    cwd: options.projectPath,
    ignore: excludes.map((pattern) => `**/${pattern}/**`),
    nodir: true,
    absolute: true
  })

  // Filter by file extensions
  const filteredFiles = files.filter((file) => {
    const ext = extname(file).toLowerCase()
    return extensions.includes(ext)
  })

  return filteredFiles
}
