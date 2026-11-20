/**
 * 演示场景清单：每个场景动态注入一个脚本，
 * expect 描述自动化验收期望看到的事件。
 */

export interface Scenario {
  id: string;
  title: string;
  kind: 'attack' | 'benign';
  desc: string;
  scriptSrc?: string;
  /** SRI 场景：从篡改路由加载并校验哈希 */
  integrity?: { src: string; loadFrom: string; hash: string };
  /** 注入后多少毫秒开始断言 */
  waitMs: number;
  expect: {
    block?: boolean;
    tamper?: boolean;
    reasonIncludes?: string;
    channelIncludes?: string;
    /** 合法场景：明确不应出现 block */
    noBlock?: boolean;
  };
}

export const scenarios: Scenario[] = [
  {
    id: 'benign-vendors',
    title: '合法供应商正常运行',
    kind: 'benign',
    desc: '统计/客服/广告/A-B 四个脚本按授权工作，期望零阻断',
    scriptSrc: '/src/app/scenarios/load-benign.ts',
    waitMs: 2500,
    expect: { noBlock: true },
  },
  {
    id: 'delayed-image',
    title: '延迟触发 · 图片像素盗卡',
    kind: 'attack',
    desc: '统计脚本被篡改，8 秒后把卡号藏进图片请求外发',
    scriptSrc: '/vendor/analytics/analytics.tampered.js',
    waitMs: 9500,
    expect: { block: true, reasonIncludes: 'sensitive-fingerprint', channelIncludes: 'image' },
  },
  {
    id: 'gray-beacon',
    title: '灰度生效 · Beacon 外发',
    kind: 'attack',
    desc: '只对 25% 用户触发（URL 带 forceGray=1 可强制命中），navigator.sendBeacon 外发 PAN+CVV',
    scriptSrc: '/vendor/ads/ads.tampered.js',
    waitMs: 3000,
    expect: { block: true, reasonIncludes: 'sensitive-fingerprint', channelIncludes: 'beacon' },
  },
  {
    id: 'font-exfil',
    title: '字体请求外发（base64）',
    kind: 'attack',
    desc: '卡号经 base64 编码藏在 FontFace 的 url() 里',
    scriptSrc: '/vendor/abtest/abtest.tampered.js',
    waitMs: 3500,
    expect: { block: true, reasonIncludes: 'sensitive-fingerprint', channelIncludes: 'font' },
  },
  {
    id: 'b64-fetch',
    title: 'Base64 编码 · Fetch 外发',
    kind: 'attack',
    desc: '卡号+姓名 JSON→base64，伪装文本日志 POST',
    scriptSrc: '/vendor/chat/chat.tampered.js',
    waitMs: 3500,
    expect: { block: true, reasonIncludes: 'sensitive-fingerprint', channelIncludes: 'fetch' },
  },
  {
    id: 'split-xhr',
    title: '分片 · XHR 外发',
    kind: 'attack',
    desc: '卡号拆 4 段放进 query 参数，数字重组后仍被识别',
    scriptSrc: '/vendor/malware/split-xhr.js',
    waitMs: 3500,
    expect: { block: true, reasonIncludes: 'sensitive-fingerprint', channelIncludes: 'xhr' },
  },
  {
    id: 'ws-exfil',
    title: 'WebSocket 长连接外发',
    kind: 'attack',
    desc: '连接建立后在消息里发送卡号',
    scriptSrc: '/vendor/malware/ws-exfil.js',
    waitMs: 3000,
    expect: { block: true, channelIncludes: 'websocket' },
  },
  {
    id: 'css-exfil',
    title: 'CSS url() 外发',
    kind: 'attack',
    desc: '没有 img/fetch，数据藏进 background-image',
    scriptSrc: '/vendor/malware/css-exfil.js',
    waitMs: 3200,
    expect: { block: true, channelIncludes: 'css' },
  },
  {
    id: 'kill-guard',
    title: '反防护：探测并关停 PayGuard',
    kind: 'attack',
    desc: '重写/删除钩子、摘监听器、删脚本标签，全部应被拒绝并告警',
    scriptSrc: '/vendor/malware/kill-guard.js',
    waitMs: 3000,
    expect: { block: true, tamper: true, reasonIncludes: 'guard-tamper' },
  },
  {
    id: 'unknown-script',
    title: '未授权脚本注入',
    kind: 'attack',
    desc: '不在供应商允许名单的脚本，加载入口即被拦截',
    scriptSrc: '/vendor/unknown/unknown-inject.js',
    waitMs: 1500,
    expect: { block: true, reasonIncludes: 'unauthorized-script', channelIncludes: 'script-load' },
  },
  {
    id: 'sri-tamper',
    title: '供应链篡改 · SRI 完整性校验',
    kind: 'attack',
    desc: 'CDN 返回的脚本被注入额外代码，哈希与基线不符，运行前被摘除',
    scriptSrc: '/vendor/_tampered/analytics/analytics.js',
    waitMs: 2500,
    expect: { block: true, reasonIncludes: 'integrity-mismatch', channelIncludes: 'script-load' },
  },
];
