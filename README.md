# PayGuard · 第三方脚本页面运行时防护（演示）

针对结算页第三方脚本被篡改、窃取支付信息的运行时防护系统。在用户浏览器中持续监控
所有第三方脚本的**读取行为**与**外发通道**，发现盗取支付信息当场阻断并上报，同时保证
合法供应商功能零误伤。

## 威胁模型与覆盖能力

| 攻击手法 | 防护机制 | 对应样本 |
| --- | --- | --- |
| 延迟触发（setTimeout 休眠后动手） | 钩子常驻，无"扫描窗口期"概念 | `analytics.tampered.js`（8 秒） |
| 灰度生效（只对部分用户下手） | 每个用户独立运行，命中即拦；服务端聚合告警可见覆盖率 | `ads.tampered.js`（25% 灰度） |
| 图片像素外发 | 钩住 `Image.src/srcset/setAttribute`，URL+载荷过策略 | `analytics.tampered.js` |
| 字体请求外发 | 钩住 `FontFace` 构造器、`<link rel=preload as=font>` | `abtest.tampered.js` |
| CSS `url()` 外发 | 钩住 `CSSStyleDeclaration.setProperty` | `css-exfil.js` |
| base64 / URL 编码藏数据 | 载荷自动多层解码后再做指纹匹配 | `chat.tampered.js` |
| 分片拆分卡号 | 数字顺序重组 + Luhn 兜底；短分片由污点层兜底 | `split-xhr.js` |
| WebSocket 长连接 | 包装 `WebSocket` 构造器与实例 `send` | `ws-exfil.js` |
| fetch / XHR / beacon | 全通道包装，阻断时返回静默假响应 | 多个样本 |
| 探测并关停防护 | 钩子 `configurable:false` 锁定、`defineProperty/deleteProperty/removeEventListener` 拦截、心跳校验 | `kill-guard.js` |
| 未授权脚本注入 | 脚本加载允许名单 + SRI 完整性校验 | `unknown-inject.js` |
| 供应链篡改（CDN 投毒） | 构建期生成 SRI 清单，运行时重新拉取算哈希比对 | `/vendor/_tampered/*` 路由 |

## 架构

```
┌─────────────────────────────── index.html ───────────────────────────────┐
│  1. guard-bundle.js（IIFE，最先同步加载）                                  │
│     ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────┐  │
│     │ FieldWatcher │──▶│ SecretScanner │   │ TaintRegistry（读取污点） │  │
│     │ 敏感输入识别  │   │ 指纹库+解码扫描 │   └───────────┬──────────────┘  │
│     └──────┬───────┘   └───────────────┘               ▼                 │
│            ▼                                    ┌──────────────────┐      │
│     DOM 读取钩子（value/getAttribute）─────────▶│  PolicyEngine     │      │
│            │                                    │ 供应商×数据等级×  │      │
│  网络/资源/导航/脚本钩子 ──────────────────────▶│ 通道 允许名单决策  │      │
│            │                                    └────────┬─────────┘      │
│            ▼                                             ▼                │
│     抗关停层（锁定+心跳）                          Reporter（事件总线+     │
│                                                   beacon/fetch 上报）     │
│  2. 第三方脚本（analytics/chat/ads/…）                                    │
│  3. 应用主模块（结算表单 + 演示面板）                                      │
└───────────────────────────────────────────────────────────────────────────┘
```

### 两道独立证据，互补短板

1. **内容指纹**：用户输入的卡号（Luhn 校验通过才登记）、邮箱等生成精确/紧凑/末四位指纹，
   外发载荷经明文、URL 解码、base64（含嵌套）解码后匹配；另有 Luhn 合法 PAN 兜底发现未登记卡号。
2. **行为污点**：任何脚本读取敏感输入框（`value` getter，jQuery 等库内部同样走它）即登记
   "某供应商读了某等级字段"。即使载荷被加密/拆碎导致内容层无感，只要该供应商把数据发往
   未授权目标，污点规则直接阻断。

### 防误伤设计

- 策略是 `供应商 × 目标域名 × 数据等级 × 通道 × 路径` 的允许名单，而非关键字黑名单。
  同源结算接口、客服读姓名邮箱、广告转化像素等正常业务全部显式放行。
- 卡号必须通过 Luhn 模 10 校验才注册指纹；CVV 必须与卡号同现或带 cvc/cvv 关键字才采信。
- 阻断返回符合 API 契约的静默假响应（204 / 假 XHR 事件），恶意脚本不会立刻察觉防护存在。

## 目录结构

```
src/guard/            PayGuard SDK（TypeScript，编译为 IIFE）
  core/               纯逻辑：扫描器、策略引擎、污点、服务识别、Luhn、上报
  hooks/              浏览器 API 钩子：网络/DOM/资源/导航/脚本/抗关停
src/app/              示例结算页 + 实时事件面板 + 自动化验收
public/vendor/
  analytics|chat|ads|abtest/   合法供应商脚本 + 同名 .tampered.js 攻击样本
  malware/            分片/WebSocket/CSS/反防护样本
  unknown/            不在允许名单的注入脚本
e2e/                  Playwright 真实浏览器端到端验收（13 个用例）
tests/                Vitest 单元测试（Luhn/扫描器/策略引擎，22 个用例）
scripts/              Guard 打包 + SRI 清单生成
```

## 运行

```bash
npm install
npm run dev          # 构建 guard-bundle 并启动 http://127.0.0.1:5173
```

打开页面后：
- 左侧是结算表单（已预填 Luhn 合法测试卡号 `4242 4242 4242 4242`）；
- 右侧上半部分是场景按钮（合法对照 + 9 类攻击），点击即注入对应样本；
- 中间是实时事件面板（阻断/篡改/污点预警/敏感字段读取），事件同时 POST 到
  `/payguard/events` 并经 SSE 回推，模拟真实服务端收集链路；
- 底部"运行全部场景验收"会在页面内自动跑一遍并输出 PASS/FAIL。

## 测试

```bash
npm test             # Vitest 单元测试（22）：Luhn/扫描器/策略引擎纯逻辑
npm run typecheck    # tsc 严格模式
npm run test:e2e     # Playwright 端到端（14）：真实 Chromium + 生产构建
```

E2E 跑在 `vite preview` 的**生产构建**上（无 HMR/WebSocket 开发客户端干扰），
事件断言全部用 `expect.poll` 轮询本地防护总线，避免固定 sleep 的时序抖动。
灰度样本支持 `?forceGray=1` 强制命中灰度分支，使概率性攻击可确定性验收。

### 关键工程决策（踩坑记录）

- **同源脚本授权要独立于网络目标解析**：`/vendor/unknown/x.js` 这类同源注入不能因为
  "同源"就兜底放行，`ServiceRegistry.isAuthorizedScript` 要求命中显式路径前缀。
- **同源 WebSocket/EventSource 直接放行**：它们是页面自身基础设施（如开发服务器 HMR、
  站内推送），不应被第三方外联策略误伤。
- **原生 IDL 方法必须绑定接收者**：`window.setTimeout`、`navigator.sendBeacon`、
  `localStorage` 等脱离 window/navigator 调用会抛 `Illegal invocation`，捕获原生引用时统一 bind。
- **Location 方法在部分浏览器是实例级不可配置属性**：nav 钩子需检测描述符并优雅降级。
- **抗关停心跳基线在全部钩子安装后采集**，否则会把防护自己的包装函数误报成外部篡改。
- **阻断响应要符合 API 契约**：HTTP 204 不能带 body；XHR 阻断需手动派发 readystatechange/load 事件。

## 真实部署要点（演示之外）

1. **加载顺序是生命线**：guard-bundle 必须是文档第一个可执行脚本，建议服务端模板内联
   或用 `Content-Security-Policy: script-src` 配合，确保没有可抢先执行的内联脚本。
2. 策略配置应由服务端按页面类型下发，供应商域名/通道/数据等级最小授权。
3. SRI 清单纳入 CI：供应商脚本每次更新都重新生成哈希，篡改即拒载。
4. 客户端防护可被有准备的攻击者用原型链深层绕过、iframe 隔离等方式对抗，需与 CSP、
   服务端风控、卡片数据 tokenization（不落 DOM）组合使用，属于纵深防御的一层而非银弹。
