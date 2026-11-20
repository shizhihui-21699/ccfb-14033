/**
 * 模拟攻击者数据收集服务器（端口 4001）。
 * 如果防护生效，这台服务器应该【永远收不到】任何卡号数据。
 * 它每收到一条请求，就代表有一次外泄成功（或防护被绕过）。
 */
'use strict';
const http = require('http');

const PORT = 4001;
const C = { red: '\x1b[31m', bold: '\x1b[1m', reset: '\x1b[0m' };

http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    console.log(`${C.red}${C.bold}💀 [攻击者服务器] 收到外泄数据! ${req.method} ${req.url}${body ? '  body=' + body.slice(0, 300) : ''}${C.reset}`);
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': req.url.endsWith('.css') ? 'text/css' : 'image/gif',
    });
    res.end();
  });
}).listen(PORT, () => {
  console.log(`💀 模拟攻击者收集端: http://127.0.0.1:${PORT}/  (防护生效时这里应保持安静)`);
});
