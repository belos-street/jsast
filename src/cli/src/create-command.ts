import { CONFIG_DEFAULT } from '@/config'
import { Command } from 'commander'
import { initFiglet } from './init-figlet'
import { validateArguments } from './validate-arguments'

export const createCommand = (process: NodeJS.Process): Command => {
  //1. 初始化figlet
  console.log(initFiglet(CONFIG_DEFAULT.name))

  // 设置版本信息
  const program = new Command()
  program.version(CONFIG_DEFAULT.version, '-v, --version', 'Show version number')

  // 自定义帮助信息
  program.helpOption('-h, --help', 'Show help information').description(CONFIG_DEFAULT.description)

  // 扫描项目参数
  program.requiredOption('-p, --project <path>', '要扫描的项目目录路径（绝对路径，例如：/Users/project/src）') //如果没有就报错
  program.requiredOption('-o, --output <path>', '扫描结果输出文件路径（绝对路径，例如：/Users/project/results）') //如果不填，就默认输出到项目根目录
  program.requiredOption('-r, --rules <path>', 'ESLint规则配置文件路径（绝对路径，例如：/Users/config/security-rules.json）') //默认读取命令行给的规则配置文件路径，如果没有就读取项目根目录的jsast.config.json文件, 都没有就报错

  // 解析命令行参数
  program.parse(process.argv)

  // 获取解析后的参数
  const options = program.opts()

  // 验证参数
  const validationResult = validateArguments(options)

  // 如果验证失败，输出错误信息并退出
  if (!validationResult.isValid) {
    console.error('参数验证失败：')
    validationResult.errors.forEach((error, index) => {
      console.error(`${index + 1}. ${error}`)
    })
    process.exit(1)
  }

  // 验证通过，将标准化后的参数附加到program对象上
  ;(program as any).normalizedArguments = validationResult.normalizedArguments

  return program
}
