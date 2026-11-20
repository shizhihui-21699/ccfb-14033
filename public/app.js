/**
 * 第一方业务代码：结算流程 + 防护事件演示面板。
 * 第一方脚本（非 /vendor/ 路径）不受网络限制，可正常提交支付数据到本站。
 */
(function () {
  'use strict';

  // ---- 演示用用户身份（delayed 样本只攻击偶数 uid）----
  if (!localStorage.getItem('uid')) {
    localStorage.setItem('uid', String(Math.floor(Math.random() * 100)));
  }
  var uid = localStorage.getItem('uid');
  var uidBar = document.getElementById('uid-bar');
  uidBar.innerHTML = '　当前用户 uid=<b>' + uid + '</b>（样本②只攻击偶数 uid）' +
    ' <a href="javascript:void 0" id="reuid">换一个身份</a>';
  document.getElementById('reuid').onclick = function () {
    localStorage.setItem('uid', String(Math.floor(Math.random() * 100)));
    location.reload();
  };

  // ---- 正常结算流程 ----
  document.getElementById('fill-test').onclick = function () {
    document.getElementById('card-number').value = '4242 4242 4242 4242';
    document.getElementById('card-name').value = 'ZHANG SAN';
    document.getElementById('card-expiry').value = '12/28';
    document.getElementById('card-cvv').value = '123';
    ['card-number', 'card-name', 'card-expiry', 'card-cvv'].forEach(function (id) {
      document.getElementById(id).dispatchEvent(new Event('input', { bubbles: true }));
    });
  };

  document.getElementById('pay-form').addEventListener('submit', function (e) {
    e.preventDefault();
    fetch('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        card: document.getElementById('card-number').value,
        name: document.getElementById('card-name').value,
        expiry: document.getElementById('card-expiry').value,
        cvv: document.getElementById('card-cvv').value
      })
    }).then(function (r) { return r.json(); })
      .then(function (d) {
        document.getElementById('order-result').textContent = '✅ 支付成功，订单号 ' + d.orderId;
      });
  });

  // ---- 防护事件面板 ----
  var logEl = document.getElementById('shield-log');
  var listBody = document.querySelector('#script-list tbody');
  var scriptRows = {};

  function short(url) { return url.replace(location.origin, ''); }

  function renderScripts() {
    listBody.innerHTML = '';
    Object.keys(scriptRows).forEach(function (url) {
      var s = scriptRows[url];
      var tr = document.createElement('tr');
      var status = s.blocked ? '<span class="pill bad">已隔离</span>'
        : s.marks.size ? '<span class="pill warn">可疑</span>'
        : '<span class="pill ok">正常</span>';
      tr.innerHTML = '<td>' + (s.third ? '🧩' : '🏠') + ' ' + short(url) + '</td>' +
        '<td>' + Array.from(s.marks).join('<br>') + '</td><td>' + status + '</td>';
      listBody.appendChild(tr);
    });
  }

  function log(cls, msg) {
    var div = document.createElement('div');
    div.className = cls;
    div.textContent = new Date().toLocaleTimeString() + '  ' + msg;
    logEl.appendChild(div);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function ensureScript(url, third) {
    if (!scriptRows[url]) scriptRows[url] = { third: third, marks: new Set(), blocked: false };
    return scriptRows[url];
  }

  window.addEventListener('shield:event', function (e) {
    var d = e.detail;
    switch (d.name) {
      case 'ready':
        log('ready', '🛡️ 防护探针已就绪，开始盯守第三方脚本');
        break;
      case 'script-seen':
        ensureScript(d.script, d.third);
        log('allow', '发现脚本 ' + short(d.script));
        renderScripts();
        break;
      case 'mark':
        ensureScript(d.script, true).marks.add(d.tag);
        log('mark', '⚠️ 可疑行为 [' + d.tag + '] ← ' + short(d.script));
        renderScripts();
        break;
      case 'block':
        log('block', '🛑 已阻断 ' + d.api + ' → ' + d.url + '（原因: ' + d.reason + '，脚本: ' + short(d.script || '?') + '）');
        break;
      case 'quarantine':
        if (scriptRows[d.script]) scriptRows[d.script].blocked = true;
        log('quarantine', '🔒 已隔离 ' + short(d.script) + '，摘除其 ' + d.removedListeners + ' 个事件监听器');
        renderScripts();
        break;
      case 'tamper':
        log('tamper', '🚨 检测到反防护行为：' + d.target + ' 钩子被替换，已自动恢复');
        break;
      case 'lockdown':
        log('lockdown', '🚨 兜底扫描发现污点资源 ' + d.url + '，已进入全局长锁');
        break;
      case 'iframe-guarded':
        log('allow', '已为同源 iframe 注入防护');
        break;
    }
  });

  log('allow', '面板已启动，等待探针事件…');
})();
