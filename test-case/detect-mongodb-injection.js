// MongoDB注入检测测试用例

// 场景1: $where 操作符使用字符串拼接（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.find({ $where: "this.name == '" + userInput + "'" })

// 场景2: $where 操作符使用模板字符串（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.find({ $where: `this.name == '${userInput}'` })

// 场景3: $where 操作符在 findOne 中使用（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.findOne({ $where: 'this.age > ' + ageInput })

// 场景4: $where 操作符在 update 中使用（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.update({ $where: 'this.name == ' + nameInput }, { $set: { active: true } })

// 场景5: $where 操作符在 deleteMany 中使用（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.deleteMany({ $where: 'this.status == ' + statusInput })

// 场景6: 直接使用用户输入作为查询条件（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.find({ name: userInput })

// 场景7: 直接使用用户输入在 findOne 中（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.findOne({ email: userEmail })

// 场景8: 直接使用用户输入在 update 中（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.update({ id: userId }, { $set: { name: newName } })

// 场景9: 直接使用用户输入在 deleteOne 中（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.deleteOne({ _id: deleteId })

// 场景10: 多个字段直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误（2个问题）
db.collection.find({ name: userName, age: userAge })

// 场景11: Mongoose 模型使用 $where（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
User.find({ $where: "this.name == '" + userInput + "'" })

// 场景12: Mongoose 模型直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Product.find({ category: userCategory })

// 场景13: Mongoose 模型 findOne 直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Order.findOne({ orderId: userOrderId })

// 场景14: Mongoose 模型 update 直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
User.update({ email: userEmail }, { $set: { verified: true } })

// 场景15: 静态字符串查询（安全）
// 预期: 不触发规则警告
db.collection.find({ name: 'John' })

// 场景16: 使用 $eq 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ name: { $eq: userInput } })

// 场景17: 使用 $in 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ id: { $in: userIds } })

// 场景18: 使用 $gt 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ age: { $gt: minAge } })

// 场景19: 使用 $lt 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ price: { $lt: maxPrice } })

// 场景20: 使用 $regex 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ name: { $regex: namePattern } })

// 场景21: 使用 ObjectId 构造函数（安全）
// 预期: 不触发规则警告
db.collection.find({ _id: new ObjectId(userId) })

// 场景22: Mongoose findById 方法（安全）
// 预期: 不触发规则警告
User.findById(userId)

// 场景23: Mongoose findOne 使用 ObjectId（安全）
// 预期: 不触发规则警告
User.findOne({ _id: new ObjectId(userId) })

// 场景24: 静态 $where 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ $where: 'this.age > 18' })

// 场景25: 空对象查询（安全）
// 预期: 不触发规则警告
db.collection.find({})

// 场景26: 嵌套对象直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
db.collection.find({ address: { city: userCity } })

// 场景27: 数组查询使用操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ tags: { $all: userTags } })

// 场景28: $or 操作符中直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误（2个问题）
db.collection.find({ $or: [{ name: userName }, { email: userEmail }] })

// 场景29: $and 操作符中直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误（2个问题）
db.collection.find({ $and: [{ age: userAge }, { status: userStatus }] })

// 场景30: 非数据库函数调用（安全）
// 预期: 不触发规则警告
console.log(userInput)

// 场景31: Math.random() 调用（安全）
// 预期: 不触发规则警告
const x = Math.random()

// 场景32: 多个 $where 操作符（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误（2个问题）
db.collection.find({ $where: "this.name == '" + userInput + "'" })
db.collection.findOne({ $where: 'this.age > ' + ageInput })

// 场景33: 混合 $where 和直接用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误（2个问题）
db.collection.find({ $where: "this.name == '" + userInput + "'" })
db.collection.find({ name: userName })

// 场景34: Mongoose Product 模型直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Product.find({ price: userPrice })

// 场景35: Mongoose Order 模型直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Order.find({ status: userStatus })

// 场景36: Mongoose Account 模型直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Account.find({ username: userUsername })

// 场景37: Mongoose Session 模型直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Session.find({ token: userToken })

// 场景38: Mongoose Document 模型直接使用用户输入（不安全）
// 预期: 触发 detect-mongodb-injection 规则错误
Document.find({ title: userTitle })

// 场景39: 使用 $ne 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ status: { $ne: 'deleted' } })

// 场景40: 使用 $gte 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ age: { $gte: 18 } })

// 场景41: 使用 $lte 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ price: { $lte: 100 } })

// 场景42: 使用 $exists 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ email: { $exists: true } })

// 场景43: 使用 $type 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ age: { $type: 'number' } })

// 场景44: 使用 $mod 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ age: { $mod: [2, 0] } })

// 场景45: 使用 $size 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ tags: { $size: 3 } })

// 场景46: 使用 $all 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ tags: { $all: ['tag1', 'tag2'] } })

// 场景47: 使用 $elemMatch 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ comments: { $elemMatch: { author: 'John' } } })

// 场景48: 使用 $nor 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ $nor: [{ status: 'deleted' }, { status: 'archived' }] })

// 场景49: 使用 $not 操作符（安全）
// 预期: 不触发规则警告
db.collection.find({ age: { $not: { $lt: 18 } } })

// 场景50: 复杂查询使用操作符（安全）
// 预期: 不触发规则警告
db.collection.find({
  $and: [
    { age: { $gte: 18 } },
    { $or: [{ status: 'active' }, { status: 'pending' }] }
  ]
})
