// detect-path-traversal 测试用例

// 场景1: fs.readFile 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.readFile(`./data/${userInput}`)

// 场景2: fs.readFileSync 使用字符串拼接（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.readFileSync('./data/' + userInput)

// 场景3: fs.writeFile 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.writeFile(`./output/${filename}`, data)

// 场景4: fs.writeFileSync 使用字符串拼接（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.writeFileSync('./output/' + filename, data)

// 场景5: fs.unlink 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.unlink(`./files/${userInput}`)

// 场景6: fs.unlinkSync 使用字符串拼接（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.unlinkSync('./files/' + userInput)

// 场景7: fs.existsSync 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.existsSync(`./data/${userInput}`)

// 场景8: fs.stat 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.stat(`./data/${userInput}`)

// 场景9: fs.readdir 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.readdir(`./data/${userInput}`)

// 场景10: fs.mkdir 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.mkdir(`./data/${userInput}`)

// 场景11: fs.rmdir 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.rmdir(`./data/${userInput}`)

// 场景12: require fs 模式（不安全）
// 预期: 触发 detect-path-traversal 规则警告
require('fs').readFile(`./data/${userInput}`)

// 场景13: 直接调用 readFile 函数（不安全）
// 预期: 触发 detect-path-traversal 规则警告
readFile(`./data/${userInput}`)

// 场景14: 使用静态路径字符串（安全）
// 预期: 不触发规则警告
fs.readFile('./data/config.json')

// 场景15: 使用静态路径字符串（安全）
// 预期: 不触发规则警告
fs.readFileSync('./data/config.json')

// 场景16: fs.createReadStream 不在检测列表中（安全）
// 预期: 不触发规则警告
fs.createReadStream('./data/config.json')

// 场景17: 多个不安全的路径操作
// 预期: 触发多个 detect-path-traversal 规则警告
fs.readFile(`./data/${x}`)
fs.writeFileSync('./output/' + y, data)

// 场景18: fs.appendFile 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.appendFile(`./logs/${userInput}`, logData)

// 场景19: fs.appendFileSync 使用字符串拼接（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.appendFileSync('./logs/' + userInput, logData)

// 场景20: fs.rename 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.rename(`./old/${oldName}`, `./new/${newName}`)

// 场景21: fs.copyFile 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.copyFile(`./src/${filename}`, `./dest/${filename}`)

// 场景22: fs.access 使用模板字符串（不安全）
// 预期: 触发 detect-path-traversal 规则警告
fs.access(`./data/${userInput}`, fs.constants.R_OK)

// 场景23: 静态模板字符串（安全）
// 预期: 不触发规则警告
fs.readFile(`./data/config.json`)

// 场景24: console.log 不会触发路径遍历检测（安全）
// 预期: 不触发规则警告
console.log('./data/config.json')
