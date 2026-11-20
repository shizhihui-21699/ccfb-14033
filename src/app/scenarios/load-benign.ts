/**
 * 合法对照场景：一次性加载四个真实供应商脚本并触发它们的标准功能。
 * 期望：只有观察类事件（客服读姓名/邮箱），没有任何阻断。
 */
export async function loadBenignVendors(): Promise<void> {
  const sources = [
    '/vendor/analytics/analytics.js',
    '/vendor/chat/chat.js',
    '/vendor/ads/ads.js',
    '/vendor/abtest/abtest.js',
  ];
  await Promise.all(
    sources.map(
      (src) =>
        new Promise<void>((resolve) => {
          const s = document.createElement('script');
          s.src = src;
          s.onload = () => resolve();
          s.onerror = () => resolve();
          document.head.appendChild(s);
        }),
    ),
  );

  // 触发各供应商的标准业务行为（全部不涉及支付字段）
  window.Analytics?.init();
  window.Analytics?.track('begin_checkout', { value: 69900 });
  window.ChatWidget?.init();
  window.AdsTracker?.conversion('ORD-DEMO-1');
  try {
    await window.ABTest?.init();
  } catch {
    /* 演示环境无真实后端 */
  }
}

declare global {
  interface Window {
    Analytics?: { init(): void; track(n: string, p?: object): void };
    ChatWidget?: { init(): void; sendMessage(t: string): void };
    AdsTracker?: { conversion(id: string): void };
    ABTest?: { init(): Promise<unknown> };
  }
}
