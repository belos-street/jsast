import { CONFIG_DEFAULT } from '@/config'
import { Command } from 'commander'
import { initFiglet } from './init-figlet'
import { validateArguments } from './validate-arguments'
import type { Arguments } from '../type'

export const createCommand = (process: NodeJS.Process): { program: Command; options: Arguments } => {
  //1. 初始化figlet
  console.log(initFiglet(CONFIG_DEFAULT.name))

  // 设置版本信息
  const program = new Command()
  program.version(CONFIG_DEFAULT.version, '-v, --version', 'Show version number')

  // 自定义帮助信息
  program.helpOption('-h, --help', 'Show help information').description(CONFIG_DEFAULT.description)

  // 扫描项目参数
  program.requiredOption('-p, --project <path>', 'Project directory path to scan (e.g., /Users/project/src)')
  program.option('-o, --output <path>', 'Output file path for scan results (e.g., /Users/project/results)')
  program.option('-r, --rules <path>', 'Rule configuration file path (e.g., /Users/config/security-rules.json)')

  // 解析命令行参数
  program.parse(process.argv)

  // 验证参数
  const args = program.opts<Arguments>()
  const options = validateArguments(args)

  return {
    program,
    options
  }
}
