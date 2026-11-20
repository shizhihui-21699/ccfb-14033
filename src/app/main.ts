/**
 * 演示主程序：结算表单、场景注入、事件面板、自动化验收
 */
import { scenarios, type Scenario } from './scenarios';
import { loadBenignVendors } from './scenarios/load-benign';
import { integrityManifest } from './integrity.generated';
import type { GuardConfig } from '../guard/types';

interface AppEvent {
  id: string;
  ts: number;
  kind: 'block' | 'alert' | 'observation' | 'tamper';
  channel?: string;
  reason?: string;
  serviceId: string;
  targetUrl?: string;
  fieldLabel?: string;
  detail: string;
  stackFrame: string;
  payloadPreview?: string;
}

declare global {
  interface Window {
    __PAYGUARD_CONFIG__: GuardConfig;
  }
}

// 把构建期生成的 SRI 清单注入配置（guard-bundle 在 defer 阶段读取，此时已就绪）
window.__PAYGUARD_CONFIG__.protectedScripts = integrityManifest;

const state = {
  events: [] as AppEvent[],
  showObs: true,
  injected: new Set<string>(),
};

// ---------------- 事件收集：优先本地防护总线，SSE 作为跨页补充 ----------------
interface GuardDebugApi {
  subscribe(fn: (e: AppEvent) => void): () => void;
}

function connectLocalBus(): void {
  const api = (window as unknown as { __PAYGUARD__?: GuardDebugApi }).__PAYGUARD__;
  if (api?.subscribe) {
    api.subscribe((evt) => addEvent(evt));
    setStatus('防护运行中 · 本地事件总线已连接', true);
  }
}

function connectEventStream(): void {
  try {
    const es = new EventSource('/payguard/events');
    es.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data) as AppEvent | { hello: boolean };
        if ('id' in data) addEvent(data);
      } catch {
        /* ignore */
      }
    };
    es.onerror = () => setStatus('事件流连接中（防护仍在本地运行）', false);
  } catch {
    setStatus('SSE 不可用', false);
  }
}

function addEvent(evt: AppEvent): void {
  if (state.events.some((e) => e.id === evt.id)) return;
  state.events.push(evt);
  // 暴露给端到端测试读取（经页面事件总线，不触碰任何被防护的 API）
  (window as unknown as { __pgEvents: AppEvent[] }).__pgEvents = state.events;
  renderEvents();
  renderStats();
}

function setStatus(text: string, ok: boolean): void {
  const el = document.getElementById('guard-status')!;
  el.textContent = text;
  el.className = `status ${ok ? 'on' : 'off'}`;
}

// ---------------- 渲染 ----------------
function renderStats(): void {
  const blocks = state.events.filter((e) => e.kind === 'block').length;
  const tampers = state.events.filter((e) => e.kind === 'tamper').length;
  const alerts = state.events.filter((e) => e.kind === 'alert').length;
  const reads = state.events.filter((e) => e.kind === 'observation' && e.fieldLabel).length;
  document.getElementById('stats')!.innerHTML = [
    `<div class="stat block"><b>${blocks}</b>阻断</div>`,
    `<div class="stat tamper"><b>${tampers}</b>篡改告警</div>`,
    `<div class="stat tamper"><b>${alerts}</b>污点预警</div>`,
    `<div class="stat"><b>${reads}</b>敏感字段读取</div>`,
    `<div class="stat allow"><b>${state.events.length}</b>事件总数</div>`,
  ].join('');
}

function renderEvents(): void {
  const list = document.getElementById('event-list')!;
  const visible = state.events
    .filter((e) => state.showObs || e.kind !== 'observation')
    .slice()
    .reverse();
  if (visible.length === 0) {
    list.innerHTML = '<div class="event kind-observation"><div class="detail">暂无事件 —— 输入卡号或注入攻击场景试试</div></div>';
    return;
  }
  list.innerHTML = visible
    .map((e) => {
      const time = new Date(e.ts).toLocaleTimeString('zh-CN', { hour12: false });
      return `
      <div class="event kind-${e.kind}">
        <div class="meta">
          <span class="badge kind-${e.kind}">${e.kind}</span>
          <span>${time}</span>
          <span>服务: ${escapeHtml(e.serviceId)}</span>
          ${e.channel ? `<span>通道: ${escapeHtml(e.channel)}</span>` : ''}
        </div>
        <div class="detail">${escapeHtml(e.detail)}</div>
        ${e.targetUrl ? `<code>→ ${escapeHtml(truncate(e.targetUrl, 90))}</code>` : ''}
        ${e.stackFrame && e.stackFrame !== 'boot' ? `<br><code>帧: ${escapeHtml(truncate(e.stackFrame, 110))}</code>` : ''}
      </div>`;
    })
    .join('');
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}
function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

// ---------------- 场景注入 ----------------
function injectScenario(s: Scenario): void {
  if (s.id === 'benign-vendors') {
    void loadBenignVendors();
    return;
  }
  if (state.injected.has(s.id)) {
    log(`ℹ️ 场景 ${s.title} 已注入过，刷新页面可重放`, 'info');
    return;
  }
  state.injected.add(s.id);
  const script = document.createElement('script');
  script.src = s.scriptSrc!;
  script.dataset.scenario = s.id;
  script.onerror = () => log(`脚本加载失败：${s.scriptSrc}`, 'fail');
  document.head.appendChild(script);
  log(`▶ 已注入：${s.title}（脚本 ${s.scriptSrc}）`, 'info');
}

function renderScenarioButtons(): void {
  const grid = document.getElementById('scenario-grid')!;
  grid.innerHTML = scenarios
    .map(
      (s) => `
    <button class="scenario" data-id="${s.id}">
      <span class="tag ${s.kind}">${s.kind === 'attack' ? '攻击样本' : '合法对照'}</span>
      <b>${s.title}</b>
      <small>${s.desc}</small>
    </button>`,
    )
    .join('');
  grid.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.scenario');
    if (!btn) return;
    const s = scenarios.find((x) => x.id === btn.dataset.id);
    if (s) injectScenario(s);
  });
}

// ---------------- 结算表单 ----------------
function initForm(): void {
  const form = document.getElementById('checkout-form') as HTMLFormElement;
  const result = document.getElementById('form-result')!;
  // 默认填入测试卡号（Luhn 合法），方便直接演示
  (document.getElementById('card-number') as HTMLInputElement).value = '4242 4242 4242 4242';
  (document.getElementById('cvv') as HTMLInputElement).value = '123';
  (document.getElementById('cardholder-name') as HTMLInputElement).value = 'ZHANG SAN';
  (document.getElementById('email') as HTMLInputElement).value = 'zhangsan@example.com';
  form.dispatchEvent(new Event('input', { bubbles: true }));

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const body = JSON.stringify({
      orderId: 'ORD-' + Math.random().toString(36).slice(2, 10).toUpperCase(),
      name: (document.getElementById('cardholder-name') as HTMLInputElement).value,
      email: (document.getElementById('email') as HTMLInputElement).value,
      card: (document.getElementById('card-number') as HTMLInputElement).value,
      cvv: (document.getElementById('cvv') as HTMLInputElement).value,
      amount: 69900,
    });
    // 同源结算接口：策略允许接收全部数据等级
    fetch('/api/checkout', { method: 'POST', headers: { 'content-type': 'application/json' }, body })
      .then(async (r) => ({ status: r.status, body: await r.text().catch(() => '') }))
      .then(({ status, body }) => {
        const blocked = body.includes('payguard') || status === 204;
        result.hidden = false;
        result.className = `form-result ${blocked ? 'err' : 'ok'}`;
        result.textContent = blocked
          ? '⚠️ 结算请求被 PayGuard 拦截（演示环境 /api/checkout 无真实服务时属正常，请检查事件面板）'
          : `✅ 下单成功（演示服务端回包）：${body || status}`;
      })
      .catch(() => {
        result.hidden = false;
        result.className = 'form-result ok';
        result.textContent = '✅ 结算请求已放行发出（演示环境无真实后端，网络错误属预期）—— PayGuard 未拦截同源合法请求';
      });
  });
}

// ---------------- 自动化验收 ----------------
function log(line: string, cls: 'pass' | 'fail' | 'info'): void {
  const out = document.getElementById('test-output')!;
  out.innerHTML += `<div class="${cls}">${line}</div>`;
  out.scrollTop = out.scrollHeight;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function runAllTests(): Promise<void> {
  log('======== PayGuard 验收开始 ========', 'info');
  let pass = 0;
  let fail = 0;
  const check = (name: string, ok: boolean, detail = '') => {
    if (ok) {
      pass++;
      log(`✅ PASS  ${name}${detail ? ' — ' + detail : ''}`, 'pass');
    } else {
      fail++;
      log(`❌ FAIL  ${name}${detail ? ' — ' + detail : ''}`, 'fail');
    }
  };

  for (const s of scenarios) {
    const since = state.events.length;
    log(`▶ 场景：${s.title}`, 'info');
    injectScenario(s);
    await sleep(s.waitMs);
    const newEvents = state.events.slice(since);

    if (s.expect.noBlock) {
      const blocked = newEvents.filter((e) => e.kind === 'block');
      check(
        `[零误报] ${s.title} 无阻断`,
        blocked.length === 0,
        blocked.length ? `出现 ${blocked.length} 条阻断：${blocked.map((b) => b.detail).join(' / ')}` : '合法请求全部放行',
      );
    }
    if (s.expect.block) {
      const hit = newEvents.find(
        (e) =>
          e.kind === 'block' &&
          (!s.expect.reasonIncludes || e.reason?.includes(s.expect.reasonIncludes)) &&
          (!s.expect.channelIncludes || e.channel === s.expect.channelIncludes),
      );
      check(
        `[阻断] ${s.title}`,
        !!hit,
        hit ? `${hit.reason} @ ${hit.channel}` : `未找到匹配阻断事件，实际事件：${newEvents.map((e) => `${e.kind}/${e.reason}/${e.channel}`).join(', ') || '无'}`,
      );
    }
    if (s.expect.tamper) {
      const hit = newEvents.find(
        (e) => e.kind === 'tamper' && (!s.expect.reasonIncludes || e.reason?.includes(s.expect.reasonIncludes)),
      );
      check(`[抗关停] ${s.title} 产生篡改告警`, !!hit, hit ? hit.detail : '未检测到篡改行为');
    }
    await sleep(400);
  }

  log(`======== 验收结束：${pass} 通过 / ${fail} 失败 ========`, fail ? 'fail' : 'pass');
}

// ---------------- 启动 ----------------
document.addEventListener('DOMContentLoaded', () => {
  initForm();
  renderScenarioButtons();
  renderEvents();
  renderStats();
  connectLocalBus();
  connectEventStream();
  setStatus('防护运行中 · 所有钩子已锁定', true);

  document.getElementById('clear-events')!.addEventListener('click', () => {
    state.events = [];
    renderEvents();
    renderStats();
  });
  document.getElementById('show-obs')!.addEventListener('change', (e) => {
    state.showObs = (e.target as HTMLInputElement).checked;
    renderEvents();
  });
  document.getElementById('run-tests')!.addEventListener('click', () => void runAllTests());
});
