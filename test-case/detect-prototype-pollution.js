// 场景1: 检测Object.prototype直接赋值
// 预期: 触发detect-prototype-pollution规则警告
Object.prototype[key] = value

// 场景2: 检测__proto__直接赋值
// 预期: 触发detect-prototype-pollution规则警告
obj.__proto__ = value

// 场景3: 检测constructor.prototype直接赋值
// 预期: 触发detect-prototype-pollution规则警告
obj.constructor.prototype[key] = value

// 场景4: 检测Object.assign使用__proto__属性
// 预期: 触发detect-prototype-pollution规则警告
Object.assign(target, { __proto__: malicious })

// 场景5: 检测Object.defineProperty使用__proto__属性
// 预期: 触发detect-prototype-pollution规则警告
Object.defineProperty(obj, "__proto__", { value: malicious })

// 场景6: 检测Object.create使用__proto__属性
// 预期: 触发detect-prototype-pollution规则警告
Object.create({ __proto__: malicious })

// 场景7: 检测Object.setPrototypeOf使用不受信任的输入
// 预期: 触发detect-prototype-pollution规则警告
Object.setPrototypeOf(obj, maliciousInput)

// 场景8: 检测Reflect.defineProperty使用__proto__属性
// 预期: 触发detect-prototype-pollution规则警告
Reflect.defineProperty(obj, "__proto__", { value: malicious })

// 场景9: 检测lodash.merge使用不受信任的输入
// 预期: 触发detect-prototype-pollution规则警告
lodash.merge(target, userInput)

// 场景10: 检测_.merge使用不受信任的输入
// 预期: 触发detect-prototype-pollution规则警告
_.merge(target, userInput)

// 场景11: 检测jQuery.extend使用不受信任的输入
// 预期: 触发detect-prototype-pollution规则警告
jQuery.extend(target, userInput)

// 场景12: 检测$.extend使用不受信任的输入
// 预期: 触发detect-prototype-pollution规则警告
$.extend(target, userInput)

// 场景13: 检测展开运算符使用__proto__属性
// 预期: 触发detect-prototype-pollution规则警告
const result = { ...target, ...{ __proto__: malicious } }

// 场景14: 检测Object.assign使用计算属性
// 预期: 触发detect-prototype-pollution规则警告
Object.assign(target, { [key]: value })

// 场景15: 检测Object.prototype使用计算属性
// 预期: 触发detect-prototype-pollution规则警告
Object.prototype[userKey] = value

// 场景16: 检测__proto__使用字符串字面量
// 预期: 触发detect-prototype-pollution规则警告
obj["__proto__"] = value

// 场景17: 检测constructor.prototype使用计算属性
// 预期: 触发detect-prototype-pollution规则警告
obj.constructor.prototype[userKey] = value

// 场景18: 检测lodash.merge使用嵌套__proto__
// 预期: 触发detect-prototype-pollution规则警告
lodash.merge(target, { nested: { __proto__: malicious } })

// 场景19: 检测lodash.merge使用constructor属性
// 预期: 触发detect-prototype-pollution规则警告
lodash.merge(target, { constructor: { prototype: malicious } })

// 场景20: 检测lodash.merge使用prototype属性
// 预期: 触发detect-prototype-pollution规则警告
lodash.merge(target, { prototype: malicious })

// 场景21: 不检测安全的Object.assign（安全）
// 预期: 不触发规则警告
Object.assign(target, { name: "test" })

// 场景22: 不检测安全的属性赋值（安全）
// 预期: 不触发规则警告
obj.name = "test"

// 场景23: 不检测安全的Object.defineProperty（安全）
// 预期: 不触发规则警告
Object.defineProperty(obj, "name", { value: "test" })

// 场景24: 不检测安全的Object.create（安全）
// 预期: 不触发规则警告
Object.create(null)

// 场景25: 不检测安全的Object.setPrototypeOf（安全）
// 预期: 不触发规则警告
Object.setPrototypeOf(obj, null)

// 场景26: 不检测安全的Reflect.defineProperty（安全）
// 预期: 不触发规则警告
Reflect.defineProperty(obj, "name", { value: "test" })

// 场景27: 不检测安全的lodash.merge（安全）
// 预期: 不触发规则警告
lodash.merge(target, { name: "test" })

// 场景28: 不检测安全的jQuery.extend（安全）
// 预期: 不触发规则警告
jQuery.extend(target, { name: "test" })

// 场景29: 不检测安全的展开运算符（安全）
// 预期: 不触发规则警告
const result = { ...target, ...{ name: "test" } }

// 场景30: 检测Object.assign使用模板字符串键
// 预期: 触发detect-prototype-pollution规则警告
Object.assign(target, { [`${key}`]: value })

// 场景31: 检测Object.assign使用二元表达式键
// 预期: 触发detect-prototype-pollution规则警告
Object.assign(target, { [prefix + key]: value })

// 场景32: 检测Object.assign使用调用表达式键
// 预期: 触发detect-prototype-pollution规则警告
Object.assign(target, { [getKey()]: value })
