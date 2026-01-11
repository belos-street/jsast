// 场景1: 检测JSON.parse使用标识符参数
// 预期: 触发validate-json-parse规则警告
JSON.parse(userInput)

// 场景2: 检测JSON.parse使用成员表达式参数
// 预期: 触发validate-json-parse规则警告
JSON.parse(req.body)

// 场景3: 检测JSON.parse使用模板字符串参数
// 预期: 触发validate-json-parse规则警告
JSON.parse(`{"data": ${userInput}}`)

// 场景4: 检测JSON.parse使用二元表达式参数
// 预期: 触发validate-json-parse规则警告
JSON.parse(prefix + userInput)

// 场景5: 检测JSON.parse使用调用表达式参数
// 预期: 触发validate-json-parse规则警告
JSON.parse(getUserInput())

// 场景6: 不检测JSON.parse使用静态字符串（安全）
// 预期: 不触发规则警告
JSON.parse('{"name": "test"}')

// 场景7: 不检测JSON.parse使用数字字面量（安全）
// 预期: 不触发规则警告
JSON.parse('123')

// 场景8: 不检测JSON.parse使用布尔字面量（安全）
// 预期: 不触发规则警告
JSON.parse('true')

// 场景9: 不检测JSON.parse使用null字面量（安全）
// 预期: 不触发规则警告
JSON.parse('null')

// 场景10: 不检测JSON.parse使用数组字面量（安全）
// 预期: 不触发规则警告
JSON.parse('[1, 2, 3]')

// 场景11: 不检测JSON.parse使用对象字面量（安全）
// 预期: 不触发规则警告
JSON.parse('{"key": "value"}')

// 场景12: 不检测JSON.stringify（安全）
// 预期: 不触发规则警告
JSON.stringify(data)

// 场景13: 不检测其他函数调用（安全）
// 预期: 不触发规则警告
Math.random()

// 场景14: 检测JSON.parse使用嵌套成员表达式
// 预期: 触发validate-json-parse规则警告
JSON.parse(request.query.data)

// 场景15: 检测JSON.parse使用计算成员表达式
// 预期: 触发validate-json-parse规则警告
JSON.parse(obj[key])

// 场景16: 检测JSON.parse使用条件表达式
// 预期: 触发validate-json-parse规则警告
JSON.parse(condition ? userInput : fallback)

// 场景17: 检测JSON.parse使用逻辑表达式
// 预期: 触发validate-json-parse规则警告
JSON.parse(userInput || defaultData)

// 场景18: 检测JSON.parse使用可选链
// 预期: 触发validate-json-parse规则警告
JSON.parse(obj?.data)

// 场景19: 检测JSON.parse使用空值合并
// 预期: 触发validate-json-parse规则警告
JSON.parse(obj?.data ?? defaultData)
