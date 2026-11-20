/** 同时拉起商店服务器与模拟攻击者服务器 */
'use strict';
const { spawn } = require('child_process');
const path = require('path');

function run(file) {
  const p = spawn(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit' });
  p.on('exit', (code) => { console.error(`${file} exited (${code})`); process.exit(code || 1); });
}
run('server.js');
run('evil-server.js');
