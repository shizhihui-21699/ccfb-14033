/** 正常第三方脚本：广告位。加载同源素材 + 读取非敏感公开字段，不应被误伤。 */
(function () {
  'use strict';
  var img = document.createElement('img');
  img.src = '/ads/banner.png';
  img.alt = '广告';
  img.style.cssText = 'position:fixed;left:20px;bottom:20px;width:1px;height:1px;';
  document.body.appendChild(img);
  // 广告脚本常见行为：读取页面标题做上下文定向（非敏感，不应触发告警）
  document.title;
})();
