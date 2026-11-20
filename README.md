# 结算页第三方脚本运行时防护（防网页盗刷 / Magecart）

针对"第三方脚本被篡改后偷取用户银行卡号"这一类攻击（Magecart / web skimming）的
**浏览器端运行时防御**示例。不依赖对第三方脚本的静态审查——即使脚本被篡改、
延迟触发、按用户分流、用图片/字体请求隐写外发、甚至试图破坏防护本身，
也能在用户浏览器里当场发现并阻断。

## 快速开始

```bash
npm install          # 安装 typescript（编译探针）与 playwright（跑验证，可选）
npm run build        # 编译 src/monitor.ts → public/monitor.js
npm run dev          # 启动商店服务器(4000) + 模拟攻击者服务器(4001)
```

打开 http://localhost:4000/checkout.html ，用页面顶部按钮切换攻击样本：

| 场景 | URL | 攻击手法 |
|---|---|---|
| 无攻击 | `checkout.html` | 统计/客服/广告正常工作，验证零误伤 |
| ① 键盘记录型 | `?attack=basic` | keydown 记录按键，blur 时用 `Image` 像素图外发 |
| ② 延迟+分流型 | `?attack=delayed` | 潜伏 8 秒、只攻击偶数 uid，读 `.value` 后 base64 经 `fetch` 外发 |
| ③ 反防护+隐写型 | `?attack=stealth` | 用 iframe 里的原生 `fetch` 掉包防护钩子；卡号藏进字体/CSS 背景请求外发 |

验证方式：点"填入测试卡号"→ 观察页面右下方面板与两个终端窗口。
**防护生效的标志：攻击者服务器（💀）终端始终保持安静。**

自动化验证（四种场景 17 项断言）：

```bash
node test/e2e.js
```

## 防御架构

```
┌─ monitor.js（最先加载，IIFE，无全局暴露）──────────────────┐
│                                                            │
│  网络出口钩子 ──→ inspect() 统一审查 ──→ 放行 / 阻断+隔离    │
│  fetch·XHR·sendBeacon·WebSocket·Image.src·script.src·     │
│  link.href·iframe.src·setAttribute·CSS url()·表单提交      │
│                                                            │
│  污点追踪：敏感输入实时值 + 常见编码形态(URL/Base64/Hex/倒序) │
│           + 全载荷 Luhn 卡号模式扫描                        │
│                                                            │
│  行为归因：Error().stack → 具体脚本文件 → 记账              │
│   · 注册键盘监听 → 标记 keylogger-suspect                  │
│   · 读取敏感字段 → 标记 sensitive-read                     │
│   · 有标记的脚本跨域发请求 → 阻断（"读了就不许发"）          │
│                                                            │
│  隔离处决：断网 + removeEventListener 摘除其全部监听器       │
│                                                            │
│  反篡改：完整性心跳(2s)校验钩子是否被掉包 → 自动恢复+上报     │
│         应用层心跳(5s)→ 服务端检测"沉默"                    │
│         同源 iframe 自动注入同等防护                        │
│                                                            │
│  兜底：PerformanceObserver 扫全部资源 URL，发现污点 → 全局锁 │
└────────────────────────────────────────────────────────────┘
```

### 关键设计决策

1. **归因靠调用栈，不靠名单**：`Error().stack` 里第一个非探针帧就是发起调用的
   脚本文件。异步回调（setTimeout/Promise/事件监听）同样保留定义者栈帧，
   所以延迟触发逃不过归因。
2. **污点用"真实输入值"而非正则**：正则只能卡"长得像卡号"的数据；把用户
   实际输入（含 Base64/URL 编码/Hex/倒序形态）作为污点，可以抓住任意形式的
   外发。再叠加 Luhn 扫描兜底"探针没看到的输入"（如恶意脚本自建隐藏输入框）。
3. **"读了就不许发"行为规则**：第三方脚本一旦注册键盘监听或读取敏感字段，
   它对非第一方源的一切网络请求都会被拒——即使外发编码是探针没见过的形态。
   这是对抗未知编码/加密外发的关键一层。
4. **第一方完全豁免**：本站代码（`app.js`）提交支付数据到本站不受任何限制，
   第三方脚本访问同源端点也不受限——误伤面被压缩到"第三方 + 跨域 + （带污点
   或有前科）"这个交集里。
5. **阻断要"像网络故障"**：fetch 返回 rejected promise、beacon 返回 false、
   图片换成透明像素——不给恶意代码明确的"被发现了"信号，同时保留现场上报。

## 生产化还需要做什么（本示例的边界）

- **CSP 是第一道墙**：`connect-src`/`img-src`/`font-src` 白名单能在浏览器层面
  直接掐断大部分外发，运行时探针是 CSP 之后的第二道（CSP 无法做内容级判断）。
- **资源注入规则需配白名单**：现实中第三方脚本常从自己 CDN 拉子资源，应把
  "非第一方即拒"改成按脚本维度的域名白名单（配置已预留 `allowedOrigins`）。
- **SRI + 子资源版本锁定**：对可静态钉住的第三方脚本用 `integrity` 属性，
  被篡改直接拒绝执行，比运行时检测更便宜。
- **上报通道加固**：示例用 sendBeacon 同源上报；生产应走独立域 + 签名，
  防止恶意脚本伪造/淹没告警。
- **已知盲区**：`document.cookie` 读取、Service Worker 注册、WebRTC、
  跨域 iframe 内部（浏览器安全边界）、`innerHTML` 注入的内联脚本
  （不触发 setter，依赖 MutationObserver 补检，存在微任务级竞态）。
- **性能**：探针全部钩子同步执行，实测单次审查 < 0.1ms；生产环境建议对
  事件上报做采样与批量合并。

## 目录结构

```
src/monitor.ts                 防护探针（TypeScript 源码，唯一需要构建的文件）
public/checkout.html           示例结算页（含探针配置）
public/app.js                  第一方业务代码 + 演示面板
public/vendor/                 正常第三方脚本（统计/客服/广告）
public/vendor/tampered/        ⚠️ 三个被篡改的脚本样本（仅用于防御测试）
server/server.js               商店服务器（静态托管 + 安全事件接收 + 心跳监控）
server/evil-server.js          模拟攻击者数据收集端（防护生效时应保持安静）
test/e2e.js                    Playwright 端到端验证（4 场景 17 项断言）
```
