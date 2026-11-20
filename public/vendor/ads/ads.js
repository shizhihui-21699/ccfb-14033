/**
 * 合法供应商 3：广告转化 ads.js
 * 行为：结算成功后用图片像素上报一次转化事件（只带订单号，无支付数据）。
 * 图片像素是广告行业标准做法 —— 期望 PayGuard 放行无敏感数据的像素请求。
 */
(function () {
  const PIXEL = '/vendor/ads/pixel.gif';

  window.AdsTracker = {
    conversion(orderId) {
      const img = new Image();
      img.alt = '';
      img.src = `${PIXEL}?order=${encodeURIComponent(orderId)}&campaign=spring_sale`;
      document.body.appendChild(img);
    },
  };
})();
