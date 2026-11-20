/**
 * 商店服务器（端口 4000）：托管结算页、第三方脚本、安全事件接收端点。
 * 仅用于本地演示，无第三方依赖。
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'public');
const PORT = 4000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
};

const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', gray: '\x1b[90m', cyan: '\x1b[36m', reset: '\x1b[0m' };
const events = [];
let lastHeartbeat = 0;
let heartbeatWarned = false;

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(data));
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);

  // ---- 安全端点 ----
  if (u.pathname === '/_sec/report' && req.method === 'POST') {
    const body = await readBody(req);
    let evt;
    try { evt = JSON.parse(body); } catch { evt = { kind: 'unparseable', raw: body.slice(0, 200) }; }
    events.push(evt);
    if (events.length > 300) events.shift();
    const tag = evt.kind === 'block' || evt.kind === 'quarantine' ? C.red
      : evt.kind === 'tamper' || evt.kind === 'lockdown' ? C.yellow : C.cyan;
    console.log(`${tag}[SHIELD/${evt.kind}]${C.reset} script=${evt.script || '-'} api=${evt.api || ''} reason=${evt.reason || evt.tag || evt.target || ''} url=${evt.url || ''}`);
    res.writeHead(204); return res.end();
  }
  if (u.pathname === '/_sec/heartbeat' && req.method === 'POST') {
    lastHeartbeat = Date.now();
    heartbeatWarned = false;
    res.writeHead(204); return res.end();
  }
  if (u.pathname === '/_sec/events') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(events));
  }

  // ---- 正常业务端点 ----
  if (u.pathname === '/api/checkout' && req.method === 'POST') {
    await readBody(req);
    console.log(`${C.green}[业务] 收到正常结算请求（第一方，敏感数据允许到达）${C.reset}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, orderId: 'ORD-' + Date.now() }));
  }
  if (u.pathname === '/collect' && req.method === 'POST') {
    await readBody(req);
    console.log(`${C.gray}[统计] analytics 上报（正常第三方行为）${C.reset}`);
    res.writeHead(204); return res.end();
  }
  if (u.pathname === '/api/chat/init' && req.method === 'POST') {
    await readBody(req);
    console.log(`${C.gray}[客服] chat-widget 初始化（正常第三方行为）${C.reset}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true }));
  }
  if (u.pathname === '/ads/banner.png') {
    console.log(`${C.gray}[广告] 加载广告位素材（正常第三方行为）${C.reset}`);
    const gif = Buffer.from('R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==', 'base64');
    res.writeHead(200, { 'Content-Type': 'image/gif' });
    return res.end(gif);
  }

  // ---- 静态文件 ----
  let p = u.pathname === '/' ? '/checkout.html' : u.pathname;
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});

// 心跳沉默检测：探针被杀死/页面被劫持时报警
setInterval(() => {
  if (lastHeartbeat && !heartbeatWarned && Date.now() - lastHeartbeat > 15000) {
    heartbeatWarned = true;
    console.log(`${C.red}[SHIELD/heartbeat] ⚠️ 客户端心跳丢失超过 15 秒——探针可能已被破坏！${C.reset}`);
  }
}, 5000);

server.listen(PORT, () => {
  console.log(`🛒 商店结算页:  http://localhost:${PORT}/checkout.html`);
  console.log(`   攻击样本开关: ?attack=basic | delayed | stealth | (不带参数=无攻击)`);
});
