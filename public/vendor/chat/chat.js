/**
 * 合法供应商 2：在线客服 chat.js
 * 行为：读取姓名/邮箱预填聊天工单（contact 级，策略允许），
 * 通过 WebSocket 发送客服消息；绝不触碰卡号/CVV —— 期望全程放行。
 */
(function () {
  const WS_URL = 'wss://chat.example.com/ws';
  let socket = null;

  function prefill() {
    // 仅读取联系信息字段
    const name = document.querySelector('#cardholder-name, input[name=name]');
    const email = document.querySelector('#email, input[name=email]');
    return {
      name: name ? name.value : '',
      email: email ? email.value : '',
    };
  }

  window.ChatWidget = {
    init() {
      // 先预填工单草稿（联系信息），不依赖连接是否建立
      const draft = prefill();
      try {
        socket = new WebSocket(WS_URL);
        socket.addEventListener('open', () => {
          socket.send(JSON.stringify({ type: 'hello', ...draft }));
        });
        socket.addEventListener('close', () => {
          socket = null;
        });
      } catch (err) {
        console.info('[chat] WebSocket 不可用（演示环境无真实 WS 服务）', err);
      }
    },
    sendMessage(text) {
      if (socket && socket.readyState === 1) {
        socket.send(JSON.stringify({ type: 'message', text }));
      }
    },
  };
})();
