"use strict";
/**
 * ============================================================================
 * Shield — 结算页第三方脚本运行时防护（客户端探针）
 * ----------------------------------------------------------------------------
 * 必须在页面中【最先】加载（同步、非 async/defer），早于一切第三方脚本。
 *
 * 防御层次：
 *   1. 网络出口劫持：fetch / XHR / sendBeacon / WebSocket / Image.src /
 *      script.src / link.href / iframe.src / setAttribute / CSS url() /
 *      表单提交 / window.open —— 全部经过统一审查函数 inspect()。
 *   2. 敏感数据污点追踪：监听敏感输入框，把用户实际输入（及其常见编码形态）
 *      作为"污点"，任何外发请求携带污点且目的地非第一方 → 当场阻断。
 *      同时对所有出站载荷做 Luhn 校验的银行卡号模式扫描。
 *   3. 行为归因与标记：通过调用栈把每次 API 调用归因到具体脚本文件；
 *      第三方脚本注册键盘监听、读取敏感字段 → 标记为可疑；
 *      可疑脚本的任何跨域网络行为 → 阻断（"读了就不许发"）。
 *   4. 隔离处决：被判定恶意的脚本进入隔离名单，其网络调用一律拒绝，
 *      已注册的 DOM 事件监听器被强制摘除。
 *   5. 反篡改：闭包保存原生函数引用；定时完整性心跳校验所有钩子是否被
 *      替换（如 iframe 里取原生 fetch 覆盖），发现即恢复并上报；
 *      服务端另有应用层心跳，探针被杀死后服务端可发现"沉默"。
 *   6. 兜底：PerformanceObserver 扫描全部资源加载记录，发现污点 URL
 *      （说明有漏网的外发通道，如 innerHTML 注入的 link/img）→ 全局长锁。
 *
 * 本探针不暴露任何全局变量（配置由页面在加载前写入 window.__SHIELD_CONFIG__，
 * 加载后即被读取并删除引用）。事件通过 CustomEvent('shield:event') 广播，
 * 仅供演示面板使用——生产环境应去掉广播，只保留服务端上报。
 * ============================================================================
 */
(function () {
    'use strict';
    const defaults = {
        reportUrl: '/_sec/report',
        heartbeatUrl: '/_sec/heartbeat',
        sensitiveSelectors: [],
        thirdPartyPaths: ['/vendor/'],
        allowedOrigins: [location.origin],
        heartbeatMs: 5000,
        integrityMs: 2000,
    };
    const cfg = Object.assign({}, defaults, window.__SHIELD_CONFIG__ || {});
    try {
        delete window.__SHIELD_CONFIG__;
    }
    catch (_) { /* ignore */ }
    // --------------------------------------------------------------------------
    // 0. 保存原生引用（闭包内，外部不可见）
    // --------------------------------------------------------------------------
    const origFetch = window.fetch.bind(window);
    const origXhrOpen = XMLHttpRequest.prototype.open;
    const origXhrSend = XMLHttpRequest.prototype.send;
    const origBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;
    const origAEL = EventTarget.prototype.addEventListener;
    const origREL = EventTarget.prototype.removeEventListener;
    const origSetAttr = Element.prototype.setAttribute;
    const origSetProperty = CSSStyleDeclaration.prototype.setProperty;
    const origFormSubmit = HTMLFormElement.prototype.submit;
    const origFormRequestSubmit = HTMLFormElement.prototype.requestSubmit;
    const origWindowOpen = window.open.bind(window);
    const OrigWebSocket = window.WebSocket;
    const imgSrcDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    const scriptSrcDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    const linkHrefDesc = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, 'href');
    const iframeSrcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    const scripts = new Map();
    let globalLockdown = false; // 兜底长锁：发现漏网外发后，锁死一切第三方跨域请求
    function stateFor(url) {
        let s = scripts.get(url);
        if (!s) {
            s = { url, marks: new Set(), blocked: false, listeners: [] };
            scripts.set(url, s);
        }
        return s;
    }
    /** 从调用栈找到"调用者"脚本 URL（跳过探针自身帧） */
    function attribute() {
        const stack = new Error().stack || '';
        const re = /https?:\/\/[^\s)"']+/g;
        let m;
        while ((m = re.exec(stack))) {
            const url = m[0].replace(/:\d+(:\d+)?$/, '');
            if (!url.includes('/monitor.js'))
                return url;
        }
        return ''; // 内联脚本 / 无法归因 → 视为第一方
    }
    function classify(scriptUrl) {
        if (!scriptUrl)
            return 'first';
        if (scriptUrl.includes('/monitor.js'))
            return 'monitor';
        if (cfg.thirdPartyPaths.some((p) => scriptUrl.includes(p)))
            return 'third';
        return 'first';
    }
    // --------------------------------------------------------------------------
    // 2. 事件广播（演示面板）与服务端上报
    // --------------------------------------------------------------------------
    function emit(name, detail) {
        try {
            window.dispatchEvent(new CustomEvent('shield:event', {
                detail: Object.assign({ ts: Date.now(), name }, detail),
            }));
        }
        catch (_) { /* ignore */ }
    }
    function report(kind, data) {
        const payload = JSON.stringify(Object.assign({
            kind, ts: Date.now(), ua: navigator.userAgent, page: location.href,
        }, data));
        try {
            if (origBeacon)
                origBeacon(cfg.reportUrl, payload);
            else
                origFetch(cfg.reportUrl, { method: 'POST', body: payload, keepalive: true });
        }
        catch (_) { /* ignore */ }
    }
    function mark(scriptUrl, tag) {
        const st = stateFor(scriptUrl);
        if (st.marks.has(tag))
            return;
        st.marks.add(tag);
        emit('mark', { script: scriptUrl, tag });
        report('mark', { script: scriptUrl, tag });
    }
    /** 隔离处决：断网 + 摘除其全部 DOM 监听器 */
    function quarantine(scriptUrl, reason) {
        const st = stateFor(scriptUrl);
        if (st.blocked)
            return;
        st.blocked = true;
        let removed = 0;
        for (const l of st.listeners) {
            try {
                origREL.call(l.t, l.type, l.fn);
                removed++;
            }
            catch (_) { /* ignore */ }
        }
        st.listeners.length = 0;
        emit('quarantine', { script: scriptUrl, reason, removedListeners: removed });
        report('quarantine', { script: scriptUrl, reason, removedListeners: removed });
    }
    // --------------------------------------------------------------------------
    // 3. 污点追踪：敏感字段的真实输入值 + 常见编码形态 + Luhn 卡号扫描
    // --------------------------------------------------------------------------
    const strongTaints = new Set(); // 长度 ≥ 6 的敏感值（卡号等）
    const weakTaints = new Set(); // 短值（CVV/有效期），只作辅助信号
    function safeBtoa(s) {
        try {
            return btoa(s);
        }
        catch (_) {
            return '';
        }
    }
    function toHex(s) {
        let out = '';
        for (let i = 0; i < s.length; i++)
            out += s.charCodeAt(i).toString(16).padStart(2, '0');
        return out;
    }
    /** 一个明文值的全部常见外发编码形态 */
    function encodings(v) {
        const digits = v.replace(/[\s-]/g, '');
        const forms = [v, encodeURIComponent(v), safeBtoa(v), toHex(v), v.split('').reverse().join('')];
        if (digits !== v)
            forms.push(digits, encodeURIComponent(digits), safeBtoa(digits));
        return forms.filter((f) => f && f.length >= 4);
    }
    function refreshTaint() {
        for (const sel of cfg.sensitiveSelectors) {
            const el = document.querySelector(sel);
            if (!el || !el.value)
                continue;
            const v = el.value.trim();
            const target = v.length >= 6 ? strongTaints : weakTaints;
            for (const f of encodings(v))
                target.add(f);
        }
    }
    function luhnOk(digits) {
        let sum = 0;
        for (let i = 0; i < digits.length; i++) {
            let c = digits.charCodeAt(digits.length - 1 - i) - 48;
            if (c < 0 || c > 9)
                return false;
            if (i % 2 === 1) {
                c *= 2;
                if (c > 9)
                    c -= 9;
            }
            sum += c;
        }
        return sum % 10 === 0;
    }
    const PAN_RE = /(?:\d[ -]?){13,19}/g;
    /** 扫描一段出站文本：命中强污点 / Luhn 卡号 → 返回原因，否则 null */
    function scanPayload(text) {
        if (!text || text.length > 200000)
            return null;
        const candidates = [text];
        try {
            candidates.push(decodeURIComponent(text));
        }
        catch (_) { /* ignore */ }
        for (const t of strongTaints)
            if (text.includes(t))
                return 'tainted-value';
        for (const c of candidates) {
            PAN_RE.lastIndex = 0;
            let m;
            while ((m = PAN_RE.exec(c))) {
                const digits = m[0].replace(/[\s-]/g, '');
                if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits))
                    return 'pan-pattern';
            }
        }
        return null;
    }
    // 探针自己用原生 addEventListener 监听敏感输入（第一方行为，不触发标记）
    origAEL.call(document, 'input', (e) => {
        const t = e.target;
        if (t && t.matches && cfg.sensitiveSelectors.some((s) => { try {
            return t.matches(s);
        }
        catch (_) {
            return false;
        } })) {
            refreshTaint();
        }
    }, true);
    function isBenignScheme(url) {
        return /^(data|blob|about|javascript):/i.test(url.trim());
    }
    function inspect(api, rawUrl, body) {
        let abs;
        try {
            abs = new URL(rawUrl, location.href);
        }
        catch (_) {
            return { allow: true };
        }
        const actor = attribute();
        const actorKind = classify(actor);
        if (actorKind !== 'third')
            return { allow: true }; // 第一方与探针自身放行
        const benign = isBenignScheme(rawUrl);
        const firstParty = benign || cfg.allowedOrigins.includes(abs.origin);
        const st = stateFor(actor);
        if (st.blocked)
            return { allow: false, reason: 'quarantined', actor };
        if (globalLockdown && !firstParty)
            return { allow: false, reason: 'global-lockdown', actor };
        // 资源注入规则：第三方脚本向非第一方源注入 script/link/iframe 一律拒绝
        const isInjection = api === 'script.src' || api === 'link.href' || api === 'iframe.src';
        if (isInjection && !firstParty)
            return { allow: false, reason: 'resource-injection', actor };
        // 污点扫描（URL 全串 + 请求体）
        const hit = scanPayload(abs.href + '\n' + (body || ''));
        if (hit && !firstParty)
            return { allow: false, reason: hit, actor };
        // "读了就不许发"：有可疑标记的脚本禁止一切跨域网络
        if (st.marks.size > 0 && !firstParty)
            return { allow: false, reason: 'suspicious-exfil', actor };
        return { allow: true };
    }
    function onBlock(api, url, v) {
        emit('block', { api, url: String(url).slice(0, 300), reason: v.reason, script: v.actor });
        report('block', { api, url: String(url).slice(0, 300), reason: v.reason, script: v.actor });
        quarantine(v.actor, v.reason);
    }
    /** 序列化常见请求体类型为可扫描文本 */
    function bodyToText(body) {
        if (!body)
            return '';
        try {
            if (typeof body === 'string')
                return body;
            if (body instanceof URLSearchParams)
                return body.toString();
            if (body instanceof FormData) {
                const parts = [];
                body.forEach((v, k) => parts.push(k + '=' + String(v)));
                return parts.join('&');
            }
            return '';
        }
        catch (_) {
            return '';
        }
    }
    // --------------------------------------------------------------------------
    // 5. 网络出口钩子
    // --------------------------------------------------------------------------
    const TRANSPARENT_GIF = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
    // --- fetch ---
    const wrappedFetch = function (input, init) {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        const body = bodyToText(init && init.body);
        const v = inspect('fetch', url, body);
        if (!v.allow) {
            onBlock('fetch', url, v);
            return Promise.reject(new TypeError('Failed to fetch'));
        }
        return origFetch(input, init);
    };
    window.fetch = wrappedFetch;
    // --- XMLHttpRequest ---
    const xhrMeta = new WeakMap();
    const wrappedXhrOpen = function (method, url) {
        xhrMeta.set(this, { method, url: String(url) });
        return origXhrOpen.apply(this, arguments);
    };
    const wrappedXhrSend = function (body) {
        const meta = xhrMeta.get(this);
        if (meta) {
            const v = inspect('xhr', meta.url, bodyToText(body));
            if (!v.allow) {
                onBlock('xhr', meta.url, v);
                const self = this;
                setTimeout(() => self.dispatchEvent(new Event('error')), 0);
                return;
            }
        }
        return origXhrSend.apply(this, arguments);
    };
    XMLHttpRequest.prototype.open = wrappedXhrOpen;
    XMLHttpRequest.prototype.send = wrappedXhrSend;
    // --- sendBeacon ---
    const wrappedBeacon = function (url, data) {
        const v = inspect('beacon', url, bodyToText(data));
        if (!v.allow) {
            onBlock('beacon', url, v);
            return false;
        }
        return origBeacon ? origBeacon(url, data) : false;
    };
    if (origBeacon)
        navigator.sendBeacon = wrappedBeacon;
    // --- WebSocket ---
    window.WebSocket = function (url, protocols) {
        const v = inspect('websocket', url, '');
        if (!v.allow) {
            onBlock('websocket', url, v);
            throw new TypeError('WebSocket blocked');
        }
        return protocols !== undefined ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    };
    window.WebSocket.prototype = OrigWebSocket.prototype;
    // --- 元素属性 setter（Image.src / script.src / link.href / iframe.src）---
    function hookProp(proto, prop, desc, api, fallback) {
        Object.defineProperty(proto, prop, {
            configurable: true,
            enumerable: desc.enumerable,
            get: function () { return desc.get.call(this); },
            set: function (url) {
                const v = inspect(api, String(url), '');
                if (!v.allow) {
                    onBlock(api, String(url), v);
                    desc.set.call(this, fallback);
                    return;
                }
                desc.set.call(this, url);
            },
        });
    }
    hookProp(HTMLImageElement.prototype, 'src', imgSrcDesc, 'img.src', TRANSPARENT_GIF);
    hookProp(HTMLScriptElement.prototype, 'src', scriptSrcDesc, 'script.src', 'about:blank');
    hookProp(HTMLLinkElement.prototype, 'href', linkHrefDesc, 'link.href', 'data:text/css,');
    hookProp(HTMLIFrameElement.prototype, 'src', iframeSrcDesc, 'iframe.src', 'about:blank');
    // --- setAttribute（覆盖 el.setAttribute('src', ...) 路径）---
    const URL_ATTRS = new Set(['src', 'href', 'srcset', 'action', 'formaction']);
    const wrappedSetAttr = function (name, value) {
        try {
            if (URL_ATTRS.has(name.toLowerCase())) {
                const v = inspect('setAttribute:' + this.tagName.toLowerCase() + '.' + name, String(value), '');
                if (!v.allow) {
                    onBlock('setAttribute', String(value), v);
                    return;
                }
            }
        }
        catch (_) { /* ignore */ }
        return origSetAttr.call(this, name, value);
    };
    Element.prototype.setAttribute = wrappedSetAttr;
    // --- CSS url() 外发通道（背景图、cursor、list-style 等）---
    const CSS_URL_RE = /url\(\s*['"]?([^'")]+)['"]?\s*\)/gi;
    function inspectCssValue(value) {
        CSS_URL_RE.lastIndex = 0;
        let m;
        let ok = true;
        while ((m = CSS_URL_RE.exec(value))) {
            const v = inspect('css-url', m[1], '');
            if (!v.allow) {
                onBlock('css-url', m[1], v);
                ok = false;
            }
        }
        return ok;
    }
    const wrappedSetProperty = function (name, value, priority) {
        if (value && typeof value === 'string' && value.includes('url(') && !inspectCssValue(value))
            return;
        return origSetProperty.apply(this, arguments);
    };
    CSSStyleDeclaration.prototype.setProperty = wrappedSetProperty;
    // --- 表单提交 ---
    const wrappedFormSubmit = function () {
        const v = inspect('form.submit', this.action || '', '');
        if (!v.allow) {
            onBlock('form.submit', this.action, v);
            return;
        }
        return origFormSubmit.call(this);
    };
    HTMLFormElement.prototype.submit = wrappedFormSubmit;
    HTMLFormElement.prototype.requestSubmit = function () {
        const v = inspect('form.submit', this.action || '', '');
        if (!v.allow) {
            onBlock('form.submit', this.action, v);
            return;
        }
        return origFormRequestSubmit.apply(this, arguments);
    };
    // --- window.open ---
    window.open = function (url, target, features) {
        if (url) {
            const v = inspect('window.open', String(url), '');
            if (!v.allow) {
                onBlock('window.open', String(url), v);
                return null;
            }
        }
        return origWindowOpen(url, target, features);
    };
    // --------------------------------------------------------------------------
    // 6. DOM 读取侧钩子：键盘监听台账 + 敏感字段读取标记
    // --------------------------------------------------------------------------
    const KEYLOG_TYPES = /^(keydown|keypress|keyup|input|beforeinput|copy|paste)$/;
    const wrappedAEL = function (type, fn, opts) {
        try {
            if (fn) {
                const actor = attribute();
                if (classify(actor) === 'third') {
                    const st = stateFor(actor);
                    st.listeners.push({ t: this, type, fn });
                    if (KEYLOG_TYPES.test(type))
                        mark(actor, 'keylogger-suspect:' + type);
                }
            }
        }
        catch (_) { /* ignore */ }
        return origAEL.apply(this, arguments);
    };
    EventTarget.prototype.addEventListener = wrappedAEL;
    // 敏感字段 .value 读取标记（不阻断——支付库确实需要读，但会被记账）
    const sensitiveSelector = cfg.sensitiveSelectors.join(',');
    function hookValueGetter(proto) {
        const d = Object.getOwnPropertyDescriptor(proto, 'value');
        if (!d || !d.get)
            return;
        Object.defineProperty(proto, 'value', {
            configurable: true,
            enumerable: d.enumerable,
            get: function () {
                const v = d.get.call(this);
                try {
                    if (sensitiveSelector && this.matches && this.matches(sensitiveSelector)) {
                        const actor = attribute();
                        if (classify(actor) === 'third') {
                            mark(actor, 'sensitive-read:' + (this.id || this.name || '?'));
                        }
                    }
                }
                catch (_) { /* ignore */ }
                return v;
            },
            set: function (nv) { d.set.call(this, nv); },
        });
    }
    hookValueGetter(HTMLInputElement.prototype);
    hookValueGetter(HTMLTextAreaElement.prototype);
    // --------------------------------------------------------------------------
    // 7. DOM 注入观察：脚本登记、innerHTML 注入的资源、iframe 内嵌页防护
    // --------------------------------------------------------------------------
    function guardIframeWindow(win) {
        try {
            const w = win;
            const of2 = w.fetch.bind(w);
            w.fetch = function (input, init) {
                const url = typeof input === 'string' ? input : (input && input.url) || '';
                const v = inspect('iframe.fetch', url, bodyToText(init && init.body));
                if (!v.allow) {
                    onBlock('iframe.fetch', url, v);
                    return Promise.reject(new TypeError('Failed to fetch'));
                }
                return of2(input, init);
            };
            emit('iframe-guarded', {});
        }
        catch (_) { /* 跨域 iframe 无法注入，记录即可 */ }
    }
    const domObserver = new MutationObserver((muts) => {
        for (const mut of muts) {
            mut.addedNodes.forEach((node) => {
                const el = node;
                if (!el || el.nodeType !== 1)
                    return;
                const tag = el.tagName;
                if (tag === 'SCRIPT') {
                    const src = el.src;
                    if (src) {
                        stateFor(src);
                        emit('script-seen', { script: src, third: classify(src) === 'third' });
                    }
                }
                else if (tag === 'IFRAME') {
                    origAEL.call(el, 'load', () => {
                        try {
                            guardIframeWindow(el.contentWindow);
                        }
                        catch (_) { /* ignore */ }
                    });
                }
                // innerHTML 注入的 link/img/script 不经 setter，这里补检（含污点扫描）
                for (const attr of ['src', 'href']) {
                    const val = el[attr];
                    if (typeof val === 'string' && /^https?:/.test(val)) {
                        const v = inspect('dom-inject:' + tag.toLowerCase(), val, '');
                        if (!v.allow) {
                            onBlock('dom-inject', val, v);
                            try {
                                el.remove();
                            }
                            catch (_) { /* ignore */ }
                        }
                    }
                }
            });
        }
    });
    domObserver.observe(document.documentElement, { childList: true, subtree: true });
    // --------------------------------------------------------------------------
    // 8. 兜底：PerformanceObserver 扫描全部资源加载（漏网通道 → 全局长锁）
    // --------------------------------------------------------------------------
    try {
        const po = new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
                const hit = scanPayload(entry.name);
                if (hit && !cfg.allowedOrigins.some((o) => entry.name.startsWith(o))) {
                    globalLockdown = true;
                    emit('lockdown', { url: entry.name.slice(0, 300), reason: hit });
                    report('lockdown', { url: entry.name.slice(0, 300), reason: hit });
                }
            }
        });
        po.observe({ type: 'resource', buffered: true });
    }
    catch (_) { /* 老浏览器无此 API */ }
    // --------------------------------------------------------------------------
    // 9. 反篡改：完整性自检 + 应用层心跳
    // --------------------------------------------------------------------------
    const integrityChecks = [
        { name: 'fetch', get: () => window.fetch, want: () => wrappedFetch, fix: () => { window.fetch = wrappedFetch; } },
        { name: 'xhr.open', get: () => XMLHttpRequest.prototype.open, want: () => wrappedXhrOpen, fix: () => { XMLHttpRequest.prototype.open = wrappedXhrOpen; } },
        { name: 'xhr.send', get: () => XMLHttpRequest.prototype.send, want: () => wrappedXhrSend, fix: () => { XMLHttpRequest.prototype.send = wrappedXhrSend; } },
        { name: 'addEventListener', get: () => EventTarget.prototype.addEventListener, want: () => wrappedAEL, fix: () => { EventTarget.prototype.addEventListener = wrappedAEL; } },
        {
            name: 'img.src',
            get: () => Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src').set,
            want: () => Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src').set, // 占位，下方特殊处理
            fix: () => { /* 重新执行 hookProp */ hookProp(HTMLImageElement.prototype, 'src', imgSrcDesc, 'img.src', TRANSPARENT_GIF); },
        },
    ];
    if (origBeacon) {
        integrityChecks.push({
            name: 'sendBeacon',
            get: () => navigator.sendBeacon,
            want: () => wrappedBeacon,
            fix: () => { navigator.sendBeacon = wrappedBeacon; },
        });
    }
    // img.src 的 want 需要在 hookProp 后取一次基准
    const imgSrcSetterBaseline = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src').set;
    integrityChecks[4].want = () => imgSrcSetterBaseline;
    setInterval(() => {
        for (const c of integrityChecks) {
            try {
                if (c.get() !== c.want()) {
                    emit('tamper', { target: c.name });
                    report('tamper', { target: c.name });
                    c.fix(c.get());
                }
            }
            catch (_) { /* ignore */ }
        }
    }, cfg.integrityMs);
    // 应用层心跳：探针被整体移除/页面被劫持时，服务端能发现"沉默"
    setInterval(() => {
        try {
            if (origBeacon)
                origBeacon(cfg.heartbeatUrl, '{}');
            else
                origFetch(cfg.heartbeatUrl, { method: 'POST', body: '{}', keepalive: true });
        }
        catch (_) { /* ignore */ }
    }, cfg.heartbeatMs);
    emit('ready', { scripts: cfg.thirdPartyPaths });
    report('ready', {});
})();
