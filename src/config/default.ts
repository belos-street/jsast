// 我需要在这读取package.json的配置
import PackageJson from '../../package.json'

const { version, description, name } = PackageJson

export const CONFIG_DEFAULT = {
  version,
  description,
  name
} as const

export const FILE_NAME = {
  config: 'jsast.config.json'
} as const
