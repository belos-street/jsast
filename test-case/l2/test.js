// 测试文件：包含各种规则违反情况

const a = 1;
var b = 2; // 违反 no-var 规则

console.log('Hello World'); // 违反 no-console-log 规则

function foo() {
  var c = 3; // 违反 no-var 规则
  console.log('foo'); // 违反 no-console-log 规则
}

// 命令行注入测试案例
const child_process = require('child_process');
const userInput = 'rm -rf /';

// 不安全的用法 - 违反 no-command-injection 规则
child_process.exec('ls -la ' + userInput);
child_process.execSync('ls -la ' + userInput);
require('child_process').execFile('echo ' + userInput);

// 安全的用法 - 不违反规则
child_process.exec('ls -la');
child_process.execSync('ls -la', { shell: false });
child_process.spawn('ls', ['-la']);
