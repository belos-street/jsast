import { CONFIG_DEFAULT } from '@/config'
import { Command } from 'commander'
import { initFiglet } from './init-figlet'

export const createCommand = (process: NodeJS.Process): Command => {
  //1. 初始化figlet
  console.log(initFiglet(CONFIG_DEFAULT.name))

  // 设置版本信息
  const program = new Command()
  program.version(CONFIG_DEFAULT.version, '-v, --version', 'Show version number')

  // 自定义帮助信息
  program.helpOption('-h, --help', 'Show help information').description(CONFIG_DEFAULT.description)

  // 扫描项目参数（必填）
  //   program.requiredOption('-p, --project <path>', '要扫描的项目目录路径（绝对路径，例如：/Users/project/src）')
  //   program.requiredOption('-o, --output <path>', '扫描结果输出文件路径（绝对路径，例如：/Users/project/results）')
  //   program.requiredOption('-r, --rules <path>', 'ESLint规则配置文件路径（绝对路径，例如：/Users/config/security-rules.json）')

  // 解析命令行参数
  program.parse(process.argv)

  return program
}
