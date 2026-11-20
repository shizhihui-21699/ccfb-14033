/**
 * 端到端验证脚本：用无头 Chromium 跑四种场景，断言防护行为。
 * 运行前先启动服务器：node server/start.js
 * 用法：node test/e2e.js
 */
'use strict';
const { chromium } = require('playwright');

const BASE = 'http://localhost:4000';
const EVIL = 'http://127.0.0.1:4001';

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('  ✅ ' + name); }
  else { failed++; console.log('  ❌ ' + name + (extra ? '  -- ' + extra : '')); }
}

async function newPage(browser, attack) {
  const page = await browser.newPage();
  const shieldEvents = [];
  await page.exposeFunction('__recordShieldEvent', (e) => shieldEvents.push(e));
  await page.addInitScript(() => {
    window.__shieldEvents = [];
    window.addEventListener('shield:event', (e) => {
      window.__shieldEvents.push(e.detail);
      if (window.__recordShieldEvent) window.__recordShieldEvent(e.detail);
    });
  });
  const evilHits = [];
  page.on('request', (req) => { if (req.url().startsWith(EVIL)) evilHits.push(req.url()); });
  const failedReqs = [];
  page.on('requestfailed', (req) => { if (req.url().startsWith(EVIL)) failedReqs.push(req.url()); });
  await page.goto(BASE + '/checkout.html' + (attack ? '?attack=' + attack : ''));
  return { page, shieldEvents, evilHits, failedReqs };
}

async function fillCard(page) {
  await page.click('#fill-test');
  // 模拟真实输入触发污点追踪与 blur
  await page.click('#card-number');
  await page.keyboard.type('4');
  await page.keyboard.press('Tab');
}

(async () => {
  const browser = await chromium.launch();

  // ---------- 场景 0：无攻击，正常第三方功能不得被误伤 ----------
  console.log('\n场景 0：无攻击 —— 正常结算与第三方功能');
  {
    const { page, shieldEvents, evilHits } = await newPage(browser, '');
    await fillCard(page);
    await page.click('button[type=submit]');
    await page.waitForTimeout(1500);
    const result = await page.textContent('#order-result');
    check('正常支付成功', result && result.includes('支付成功'), result);
    check('无误伤（无 block/quarantine 事件）',
      !shieldEvents.some((e) => e.name === 'block' || e.name === 'quarantine'),
      JSON.stringify(shieldEvents.filter((e) => e.name === 'block')));
    check('探针就绪事件存在', shieldEvents.some((e) => e.name === 'ready'));
    check('攻击者服务器零请求', evilHits.length === 0, evilHits.join(','));
    await page.close();
  }

  // ---------- 场景 1：键盘记录型（图片像素外发）----------
  console.log('\n场景 1：attack=basic —— 键盘记录 + 图片像素外发');
  {
    const { page, shieldEvents, evilHits } = await newPage(browser, 'basic');
    await page.waitForTimeout(500);
    check('keydown 监听被标记为键盘记录嫌疑',
      shieldEvents.some((e) => e.name === 'mark' && String(e.tag).startsWith('keylogger-suspect')));
    await fillCard(page); // 触发 blur → 恶意 Image 外发
    await page.waitForTimeout(1500);
    check('图片像素外发被阻断', shieldEvents.some((e) => e.name === 'block' && e.api === 'img.src'),
      JSON.stringify(shieldEvents.map((e) => e.name)));
    check('恶意脚本被隔离并摘除监听器',
      shieldEvents.some((e) => e.name === 'quarantine' && e.removedListeners >= 2));
    check('攻击者服务器零请求', evilHits.length === 0, evilHits.join(','));
    // 隔离后正常支付仍可用
    await page.click('button[type=submit]');
    await page.waitForTimeout(1000);
    const result = await page.textContent('#order-result');
    check('隔离后正常支付不受影响', result && result.includes('支付成功'), result);
    await page.close();
  }

  // ---------- 场景 2：延迟触发 + 部分用户（fetch base64 外发）----------
  console.log('\n场景 2：attack=delayed —— 延迟 8s + 仅偶数 uid + fetch 外发');
  {
    // 固定偶数 uid，确保攻击激活
    const page = await (await browser.newContext()).newPage();
    const shieldEvents = [];
    await page.addInitScript(() => {
      localStorage.setItem('uid', '42');
      window.addEventListener('shield:event', (e) => window.__shieldEvents.push(e.detail));
      window.__shieldEvents = [];
    });
    const evilHits = [];
    page.on('request', (req) => { if (req.url().startsWith(EVIL)) evilHits.push(req.url()); });
    await page.goto(BASE + '/checkout.html?attack=delayed');
    await fillCard(page);
    await page.waitForTimeout(9500); // 等暗桩的 8 秒延迟触发
    const evts = await page.evaluate(() => window.__shieldEvents);
    check('敏感字段读取被标记', evts.some((e) => e.name === 'mark' && String(e.tag).startsWith('sensitive-read')),
      JSON.stringify(evts.filter((e) => e.name === 'mark')));
    check('fetch 外发被阻断', evts.some((e) => e.name === 'block' && e.api === 'fetch'));
    check('脚本被隔离', evts.some((e) => e.name === 'quarantine'));
    check('攻击者服务器零请求', evilHits.length === 0, evilHits.join(','));
    await page.close();
  }

  // ---------- 场景 3：反防护 + 字体/CSS 隐写外发 ----------
  console.log('\n场景 3：attack=stealth —— fetch 掉包 + 字体/CSS 隐写');
  {
    const { page, shieldEvents, evilHits } = await newPage(browser, 'stealth');
    await fillCard(page);
    await page.waitForTimeout(7000); // 等 4s 外发循环 + 2s 完整性心跳
    check('检测到 fetch 掉包（tamper 事件）', shieldEvents.some((e) => e.name === 'tamper'),
      JSON.stringify(shieldEvents.map((e) => e.name)));
    check('字体 link 注入被阻断', shieldEvents.some((e) => e.name === 'block' && (e.api === 'link.href' || e.api === 'dom-inject')));
    check('CSS 背景外发被阻断', shieldEvents.some((e) => e.name === 'block' && e.api === 'css-url'));
    check('被偷的 fetch 外发被阻断', shieldEvents.some((e) => e.name === 'block' && String(e.api).includes('fetch')));
    check('脚本被隔离', shieldEvents.some((e) => e.name === 'quarantine'));
    check('攻击者服务器零请求', evilHits.length === 0, evilHits.join(','));
    await page.close();
  }

  await browser.close();
  console.log('\n========================================');
  console.log(`结果：${passed} 通过, ${failed} 失败`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
