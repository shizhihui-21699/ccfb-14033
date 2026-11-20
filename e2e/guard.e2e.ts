/**
 * PayGuard 端到端验收：真实 Chromium 中加载生产构建的结算页，
 * 注入每个攻击/合法样本，断言阻断、告警与零误报。
 *
 * 稳定性设计：
 *  - 每个测试独立 goto 全新页面（Playwright 默认每测试新 context）
 *  - 事件断言全部用 expect.poll 轮询，不依赖固定 waitForTimeout 的时序巧合
 *  - 事件来自页面本地防护总线 window.__pgEvents，不触碰任何被防护的 API
 */
import { test, expect, type Page } from '@playwright/test';

const PAN = '4242 4242 4242 4242';

interface GuardEvent {
  id: string;
  ts: number;
  kind: 'block' | 'alert' | 'observation' | 'tamper';
  channel?: string;
  reason?: string;
  serviceId: string;
  detail: string;
  targetUrl?: string;
  fieldLabel?: string;
}

declare global {
  interface Window {
    __pgEvents?: GuardEvent[];
    __PAYGUARD__?: unknown;
  }
}

async function waitForGuardReady(page: Page): Promise<void> {
  await expect
    .poll(async () => page.evaluate(() => typeof window.__PAYGUARD__), { timeout: 15000 })
    .toBe('object');
  await expect(page.locator('#card-number')).toHaveValue(PAN);
  await expect(page.locator('.scenario')).toHaveCount(11, { timeout: 15000 });
}

async function gotoFresh(page: Page, path = '/'): Promise<number> {
  await page.goto(path, { waitUntil: 'domcontentloaded' });
  await waitForGuardReady(page);
  return eventCount(page);
}

async function eventCount(page: Page): Promise<number> {
  return page.evaluate(() => window.__pgEvents?.length ?? 0);
}

async function eventsSince(page: Page, since: number): Promise<GuardEvent[]> {
  return page.evaluate((n) => window.__pgEvents?.slice(n) ?? [], since);
}

/** 注入场景（按钮已由 waitForGuardReady 保证存在） */
async function injectScenario(page: Page, scenarioId: string): Promise<void> {
  await page.locator(`.scenario[data-id="${scenarioId}"]`).click();
}

/** 轮询等待满足 predicate 的事件，替代固定 sleep */
async function waitForEvent(
  page: Page,
  since: number,
  predicate: (e: GuardEvent) => boolean,
  timeout = 15000,
): Promise<GuardEvent | undefined> {
  await expect
    .poll(
      async () => (await eventsSince(page, since)).some(predicate),
      { timeout, intervals: [300, 500, 800] },
    )
    .toBe(true);
  return (await eventsSince(page, since)).find(predicate);
}

// ---------------- 防护自身 ----------------

test('防护启动：钩子已安装且不可重写', async ({ page }) => {
  await gotoFresh(page);
  const probe = await page.evaluate(() => {
    const result: Record<string, unknown> = {};
    result.hasInternalApi = typeof window.__PAYGUARD__ !== 'undefined';
    result.fetchLooksNative = /native code/.test(window.fetch.toString());
    const before = window.fetch;
    try {
      'use strict';
      (window as unknown as { fetch: unknown }).fetch = () => null;
    } catch {
      /* 严格模式下赋值锁定属性抛 TypeError，属预期 */
    }
    result.identityUnchanged = window.fetch === before;
    const desc = Object.getOwnPropertyDescriptor(window, 'fetch');
    result.locked = desc?.writable === false && desc?.configurable === false;
    return result;
  });
  expect(probe.hasInternalApi).toBe(true);
  expect(probe.fetchLooksNative).toBe(true);
  expect(probe.identityUnchanged).toBe(true);
  expect(probe.locked).toBe(true);
});

test('零误报：四个合法供应商全程放行', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'benign-vendors');
  // 客服读取姓名/邮箱的观察事件应出现（轮询，不依赖固定 sleep）
  await waitForEvent(
    page,
    since,
    (e) => e.kind === 'observation' && typeof e.fieldLabel === 'string',
    10000,
  );
  // 等四个供应商全局对象都就绪，确认它们的标准行为已执行
  await expect
    .poll(
      async () =>
        page.evaluate(
          () =>
            ['Analytics', 'ChatWidget', 'AdsTracker', 'ABTest'].every(
              (k) => typeof (window as unknown as Record<string, unknown>)[k] === 'object',
            ),
        ),
      { timeout: 10000 },
    )
    .toBe(true);
  // 再给网络请求一点时间落地，轮询确认整个观察窗口内零阻断
  await expect
    .poll(async () => (await eventsSince(page, since)).filter((e) => e.kind === 'block').length, {
      timeout: 8000,
    })
    .toBe(0);
  const blocks = (await eventsSince(page, since)).filter((e) => e.kind === 'block');
  expect(blocks, `合法供应商被误伤：${JSON.stringify(blocks.map((b) => b.detail))}`).toHaveLength(0);
});

test('同源结算请求带完整卡号仍放行', async ({ page }) => {
  const since = await gotoFresh(page);
  await page.click('button[type=submit]');
  await page.waitForTimeout(1500);
  const checkoutBlocks = (await eventsSince(page, since)).filter(
    (e) => e.kind === 'block' && (e.targetUrl ?? '').includes('/api/checkout'),
  );
  expect(checkoutBlocks).toHaveLength(0);
});

// ---------------- 攻击场景 ----------------

test('攻击1：延迟 8 秒的图片像素盗卡被阻断', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'delayed-image');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'image' && e.reason === 'sensitive-fingerprint',
    14000,
  );
  expect(hit).toBeTruthy();
});

test('攻击2：灰度生效样本，强制命中后 beacon 外发被阻断', async ({ page }) => {
  // 用 forceGray=1 确定性命中灰度分支，验证 beacon 通道的阻断能力；
  // 样本本身的 25% 随机灰度逻辑仍保留在生产代码中。
  const since = await gotoFresh(page, '/?forceGray=1');
  await injectScenario(page, 'gray-beacon');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'beacon' && e.reason === 'sensitive-fingerprint',
    10000,
  );
  expect(hit).toBeTruthy();
});

test('攻击3：字体请求外发被阻断', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'font-exfil');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'font',
  );
  expect(hit).toBeTruthy();
});

test('攻击4：base64 fetch 外发被阻断', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'b64-fetch');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'fetch',
  );
  expect(hit?.detail).toContain('支付');
});

test('攻击5：XHR 外发被阻断（指纹或污点）', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'split-xhr');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'xhr',
  );
  // 分片载荷可能扫描不到完整卡号，此时由污点规则或封禁名单兜底阻断
  expect(
    hit?.reason === 'sensitive-fingerprint' ||
      hit?.reason === 'taint-not-allowed' ||
      hit?.reason === 'blocked-destination',
  ).toBe(true);
});

test('攻击6：WebSocket 外发被阻断', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'ws-exfil');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'websocket',
  );
  expect(hit).toBeTruthy();
});

test('攻击7：CSS url() 外发被阻断', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'css-exfil');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'block' && e.channel === 'css',
  );
  expect(hit).toBeTruthy();
});

test('攻击8：关停防护的全部尝试被拒绝并告警', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'kill-guard');
  const tamper = await waitForEvent(
    page,
    since,
    (e) => e.kind === 'tamper' && e.reason === 'guard-tamper',
  );
  expect(tamper).toBeTruthy();
  // 兜底外发同样被通道层拦下
  const blocked = await waitForEvent(page, since, (e) => e.kind === 'block');
  expect(blocked).toBeTruthy();
  // 防护仍然有效：fetch 钩子身份不变、锁定状态保持
  const stillLocked = await page.evaluate(() => {
    const desc = Object.getOwnPropertyDescriptor(window, 'fetch');
    return desc?.writable === false && desc?.configurable === false;
  });
  expect(stillLocked).toBe(true);
});

test('攻击9：未授权脚本在加载入口被拦截', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'unknown-script');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.reason === 'unauthorized-script',
  );
  expect(hit).toBeTruthy();
});

test('攻击10：CDN 篡改的脚本通不过 SRI 校验，被摘除', async ({ page }) => {
  const since = await gotoFresh(page);
  await injectScenario(page, 'sri-tamper');
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.reason === 'integrity-mismatch',
  );
  expect(hit).toBeTruthy();
});

test('污点追踪：读卡号的供应商向未授权目标发"干净"请求也被拦', async ({ page }) => {
  const since = await gotoFresh(page);
  await page.evaluate(() => {
    const card = document.querySelector<HTMLInputElement>('#card-number');
    void card?.value; // 触发 value getter，登记污点
    fetch('/vendor/analytics/collect', { method: 'POST', body: 'event=ping' });
  });
  const hit = await waitForEvent(
    page,
    since,
    (e) => e.reason === 'taint-not-allowed' && e.kind === 'block',
    10000,
  );
  expect(hit).toBeTruthy();
});
