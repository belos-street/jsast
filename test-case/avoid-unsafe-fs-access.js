// 场景1: 检测 fs.readFile 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.readFile(`./data/${userInput}.txt`)

// 场景2: 检测 fs.writeFile 使用字符串拼接
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.writeFile("./output/" + fileName, data)

// 场景3: 检测 fs.unlink 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.unlink(`./temp/${id}`)

// 场景4: 检测 fs.mkdir 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.mkdir(`./logs/${date}`)

// 场景5: 检测 fs.rmdir 使用字符串拼接
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.rmdir("./cache/" + cacheId)

// 场景6: 检测 fs.readdir 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.readdir(`./uploads/${userId}`)

// 场景7: 检测 fs.stat 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.stat(`./files/${filename}`)

// 场景8: 检测 fs.existsSync 使用字符串拼接
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.existsSync("./data/" + path)

// 场景9: 检测 require fs.readFile 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
require('fs').readFile(`./data/${userInput}.txt`)

// 场景10: 检测 require fs.writeFile 使用字符串拼接
// 预期: 触发 avoid-unsafe-fs-access 规则警告
require('fs').writeFile('./output/' + fileName, data)

// 场景11: 检测直接调用 readFile 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
readFile(`./data/${userInput}.txt`)

// 场景12: 检测 fs.appendFile 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.appendFile(`./logs/${date}.log`, message)

// 场景13: 检测 fs.rename 使用模板字符串（两个路径）
// 预期: 触发 avoid-unsafe-fs-access 规则警告（2个问题）
fs.rename(`./old/${oldName}`, `./new/${newName}`)

// 场景14: 检测 fs.copyFile 使用模板字符串（两个路径）
// 预期: 触发 avoid-unsafe-fs-access 规则警告（2个问题）
fs.copyFile(`./src/${srcFile}`, `./dst/${dstFile}`)

// 场景15: 检测 fs.readFile 使用静态字符串（安全）
// 预期: 不触发规则警告
fs.readFile('./data/config.txt')

// 场景16: 检测 fs.writeFile 使用静态字符串（安全）
// 预期: 不触发规则警告
fs.writeFile('./output/result.txt', data)

// 场景17: 检测 fs.unlink 使用静态字符串（安全）
// 预期: 不触发规则警告
fs.unlink('./temp/file.txt')

// 场景18: 检测 fs.mkdir 使用静态字符串（安全）
// 预期: 不触发规则警告
fs.mkdir('./logs')

// 场景19: 检测 fs.unlinkSync 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.unlinkSync(`./temp/${id}`)

// 场景20: 检测 fs.readFileSync 使用字符串拼接
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.readFileSync("./data/" + path)

// 场景21: 检测 fs.writeFileSync 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.writeFileSync(`./output/${filename}`, data)

// 场景22: 检测 fs.mkdirSync 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.mkdirSync(`./logs/${date}`)

// 场景23: 检测 fs.rmdirSync 使用字符串拼接
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.rmdirSync("./cache/" + id)

// 场景24: 检测 fs.readdirSync 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.readdirSync(`./uploads/${userId}`)

// 场景25: 检测 fs.statSync 使用模板字符串
// 预期: 触发 avoid-unsafe-fs-access 规则警告
fs.statSync(`./files/${filename}`)

// 场景26: 检测 fs.renameSync 使用模板字符串（两个路径）
// 预期: 触发 avoid-unsafe-fs-access 规则警告（2个问题）
fs.renameSync(`./old/${oldName}`, `./new/${newName}`)

// 场景27: 检测 fs.copyFileSync 使用模板字符串（两个路径）
// 预期: 触发 avoid-unsafe-fs-access 规则警告（2个问题）
fs.copyFileSync(`./src/${srcFile}`, `./dst/${dstFile}`)
