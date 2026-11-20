/**
 * 合法供应商 4：A/B 实验平台 abtest.js
 * 行为：拉取实验分组、上报曝光，只含 usage 级数据 —— 期望全程放行。
 */
(function () {
  const API = '/vendor/abtest';

  window.ABTest = {
    async init() {
      const res = await fetch(`${API}/flags?user=anon`);
      const flags = await res.json().catch(() => ({ checkout_layout: 'A' }));
      this.flags = flags;
      navigator.sendBeacon(
        `${API}/exposure`,
        JSON.stringify({ experiment: 'checkout_layout', cohort: flags.checkout_layout }),
      );
      return flags;
    },
  };
})();
