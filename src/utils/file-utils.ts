import * as fs from 'fs/promises'
import { Dirent } from 'fs'
import * as path from 'path'

/**
 * 读取文件内容
 * @param filepath 文件路径
 * @returns 文件内容
 */
export async function readFile(filepath: string): Promise<string> {
  try {
    return await fs.readFile(filepath, 'utf-8')
  } catch (error) {
    console.error(`读取文件失败 ${filepath}:`, error)
    throw error
  }
}

/**
 * 检查文件是否为JS/TS文件
 * @param filename 文件名
 * @returns 是否为JS/TS文件
 */
export function isJsOrTsFile(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase()
  return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext)
}

/**
 * 获取目录下所有JS/TS文件
 * @param dirPath 目录路径
 * @returns JS/TS文件路径数组
 */
export async function getJsTsFilesInDirectory(dirPath: string): Promise<string[]> {
  try {
    const files = (await fs.readdir(dirPath, { withFileTypes: true })) as Dirent[]
    const jsTsFiles: string[] = []

    for (const file of files) {
      if (file.isFile() && isJsOrTsFile(file.name)) {
        jsTsFiles.push(path.join(dirPath, file.name))
      }
    }

    return jsTsFiles
  } catch (error) {
    console.error(`读取目录失败 ${dirPath}:`, error)
    throw error
  }
}
