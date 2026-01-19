// 场景1: 检测Math.random()直接调用
// 预期: 触发use-secure-random规则警告
const token = Math.random()

// 场景2: 检测Math.random()转换为字符串
// 预期: 触发use-secure-random规则警告
const sessionId = Math.random().toString(36)

// 场景3: 检测Math.random()字符串操作
// 预期: 触发use-secure-random规则警告
const id = Math.random().toString(36).substring(2)

// 场景4: 检测Math.random()数学运算
// 预期: 触发use-secure-random规则警告
const num = Math.random() * 100

// 场景5: 检测Math.random()在函数调用中
// 预期: 触发use-secure-random规则警告
console.log(Math.random())

// 场景6: 检测Math.random()在数组中
// 预期: 触发use-secure-random规则警告
const arr = [1, 2, Math.random()]

// 场景7: 检测Math.random()在对象中
// 预期: 触发use-secure-random规则警告
const obj = { random: Math.random() }


// 场景10: 检测Math.random()在模板字符串中
// 预期: 触发use-secure-random规则警告
const str = `Random: ${Math.random()}`

// 场景11: 检测Math.random()在循环中
// 预期: 触发use-secure-random规则警告
for (let i = 0; i < 10; i++) {
  console.log(Math.random())
}

// 场景12: 检测Math.random()在条件判断中
// 预期: 触发use-secure-random规则警告
if (Math.random() > 0.5) {
  console.log("heads")
}

// 场景13: 检测Math.random()在三元运算符中
// 预期: 触发use-secure-random规则警告
const result = Math.random() > 0.5 ? "heads" : "tails"

// 场景14: 检测Math.random()在逻辑表达式中
// 预期: 触发use-secure-random规则警告
const value = Math.random() || 0

// 场景15: 检测Math.random()在赋值表达式中
// 预期: 触发use-secure-random规则警告
let num1 = Math.random()

// 场景16: 检测Math.random()在一元表达式中
// 预期: 触发use-secure-random规则警告
const positive = +Math.random()

// 场景17: 检测Math.random()在更新表达式中
// 预期: 触发use-secure-random规则警告
let counter = Math.random()
counter++

// 场景18: 检测Math.random()在序列表达式中
// 预期: 触发use-secure-random规则警告
const seq = (console.log("test"), Math.random())

// 场景19: 检测Math.random()在await表达式中
// 预期: 触发use-secure-random规则警告
const awaited = await Promise.resolve(Math.random())

// 场景20: 检测Math.random()在展开运算符中
// 预期: 触发use-secure-random规则警告
const spreaded = [...[Math.random()]]

// 场景21: 检测Math.random()在new表达式中
// 预期: 触发use-secure-random规则警告
const wrapped = new Number(Math.random())

// 场景22: 检测Math.random()在this表达式中
// 预期: 触发use-secure-random规则警告
this.random = Math.random()

// 场景23: 检测Math.random()在可选链中
// 预期: 触发use-secure-random规则警告
const optional = obj?.random || Math.random()

// 场景24: 检测Math.random()在空值合并中
// 预期: 触发use-secure-random规则警告
const coalesced = obj?.random ?? Math.random()

// 场景25: 检测Math.random()在计算属性中
// 预期: 触发use-secure-random规则警告
const computed = { [Math.random()]: "value" }

// 场景26: 检测Math.random()在默认参数中
// 预期: 触发use-secure-random规则警告
function getDefault(num = Math.random()) {
  return num
}

// 场景28: 检测Math.random()在try-catch中
// 预期: 触发use-secure-random规则警告
try {
  const num = Math.random()
} catch (e) {
  console.error(e)
}

// 场景29: 检测Math.random()在switch语句中
// 预期: 触发use-secure-random规则警告
switch (Math.random() > 0.5) {
  case true:
    console.log("heads")
    break
  default:
    console.log("tails")
}

// 场景30: 检测Math.random()在while循环中
// 预期: 触发use-secure-random规则警告
while (Math.random() > 0.5) {
  console.log("test")
}

// 场景31: 检测Math.random()在do-while循环中
// 预期: 触发use-secure-random规则警告
do {
  console.log("test")
} while (Math.random() > 0.5)

// 场景32: 检测Math.random()在for-in循环中
// 预期: 触发use-secure-random规则警告
for (const key in { a: Math.random() }) {
  console.log(key)
}

// 场景33: 检测Math.random()在for-of循环中
// 预期: 触发use-secure-random规则警告
for (const num of [Math.random()]) {
  console.log(num)
}

// 场景34: 检测Math.random()在标签语句中
// 预期: 触发use-secure-random规则警告
label: {
  const num = Math.random()
}

// 场景35: 检测Math.random()在throw语句中
// 预期: 触发use-secure-random规则警告
throw new Error(Math.random().toString())

// 场景36: 检测Math.random()在import.meta中
// 预期: 触发use-secure-random规则警告
const combined = Math.random() + import.meta.url

// 场景37: 检测Math.random()在super调用中
// 预期: 触发use-secure-random规则警告
class Child extends Parent {
  constructor() {
    super(Math.random())
  }
}

// 场景38: 检测Math.random()在yield表达式中
// 预期: 触发use-secure-random规则警告
function* generator() {
  yield Math.random()
}

// 场景39: 检测Math.random()在yield*表达式中
// 预期: 触发use-secure-random规则警告
function* generator2() {
  yield* [Math.random()]
}

// 场景40: 不检测crypto.randomBytes()（安全）
// 预期: 不触发规则警告
const secureToken = crypto.randomBytes(16).toString("hex")

// 场景41: 不检测crypto.randomInt()（安全）
// 预期: 不触发规则警告
const secureNum = crypto.randomInt(1, 100)

// 场景42: 不检测crypto.randomUUID()（安全）
// 预期: 不触发规则警告
const uuid = crypto.randomUUID()

// 场景43: 不检测Math.floor()（安全）
// 预期: 不触发规则警告
const floored = Math.floor(10.5)

// 场景44: 不检测Math.PI（安全）
// 预期: 不触发规则警告
const pi = Math.PI

// 场景45: 不检测Math.E（安全）
// 预期: 不触发规则警告
const e = Math.E

// 场景46: 不检测Math.sin()（安全）
// 预期: 不触发规则警告
const sin = Math.sin(1)

// 场景47: 不检测Math.cos()（安全）
// 预期: 不触发规则警告
const cos = Math.cos(1)

// 场景48: 不检测Math.sqrt()（安全）
// 预期: 不触发规则警告
const sqrt = Math.sqrt(4)

// 场景49: 不检测Math.abs()（安全）
// 预期: 不触发规则警告
const abs = Math.abs(-1)

// 场景50: 检测Math.random()多次调用
// 预期: 触发use-secure-random规则警告（2次）
const a = Math.random()
const b = Math.random()
