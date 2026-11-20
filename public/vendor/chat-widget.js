/** 正常第三方脚本：客服气泡。渲染 UI + 同源初始化请求，不应被误伤。 */
(function () {
  'use strict';
  var bubble = document.createElement('div');
  bubble.textContent = '💬 在线客服';
  bubble.style.cssText = 'position:fixed;right:20px;bottom:20px;background:#2563eb;color:#fff;' +
    'padding:10px 16px;border-radius:20px;cursor:pointer;z-index:9999;font-size:14px;' +
    'box-shadow:0 2px 8px rgba(0,0,0,.2)';
  bubble.onclick = function () { bubble.textContent = '💬 客服小张：您好，请问有什么可以帮您？'; };
  document.body.appendChild(bubble);
  fetch('/api/chat/init', { method: 'POST', body: JSON.stringify({ page: 'checkout' }) });
})();
