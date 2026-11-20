/**
 * 合法供应商 1：流量统计 analytics.js
 * 行为：只收集页面访问、按钮点击等 usage 级数据，上报到 /vendor/analytics/collect
 * 绝不读取支付输入框 —— 期望 PayGuard 全程放行。
 */
(function () {
  const ENDPOINT = '/vendor/analytics/collect';
  const sessionId = 'sess_' + Math.random().toString(36).slice(2, 10);

  function send(event, props) {
    const payload = JSON.stringify({
      sessionId,
      event,
      props,
      ts: Date.now(),
      page: location.pathname,
    });
    // 优先 beacon，演示降级 fetch
    if (navigator.sendBeacon) {
      navigator.sendBeacon(ENDPOINT, payload);
    } else {
      fetch(ENDPOINT, { method: 'POST', body: payload });
    }
  }

  window.Analytics = {
    init() {
      send('page_view', { referrer: document.referrer || 'direct' });
      document.addEventListener(
        'click',
        (e) => {
          const tag = e.target && e.target.tagName;
          send('click', { tag, id: e.target.id || null });
        },
        true,
      );
    },
    track(name, props) {
      send(name, props || {});
    },
  };
})();
