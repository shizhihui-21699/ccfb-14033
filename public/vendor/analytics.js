/** 正常第三方脚本：统计埋点。点击监听 + 同源上报，不应被防护误伤。 */
(function () {
  'use strict';
  fetch('/collect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event: 'pageview', path: location.pathname, ts: Date.now() })
  });
  document.addEventListener('click', function (e) {
    var t = e.target;
    fetch('/collect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: 'click', tag: t && t.tagName, ts: Date.now() })
    });
  });
})();
