/* PayGuard runtime — 必须在所有第三方脚本之前加载 */
"use strict";
(() => {
  var __defProp = Object.defineProperty;
  var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
  var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

  // src/guard/core/utils.ts
  function captureNatives() {
    return {
      fetch: window.fetch.bind(window),
      XMLHttpRequest: window.XMLHttpRequest,
      sendBeacon: window.navigator.sendBeacon?.bind(window.navigator),
      defineProperty: Object.defineProperty,
      getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
      Proxy,
      Reflect,
      Error,
      atob: atob.bind(window),
      // 定时器是 window 的 IDL 方法，脱离接收者调用会抛 Illegal invocation
      setTimeout: window.setTimeout.bind(window),
      setInterval: window.setInterval.bind(window)
    };
  }
  var counter = 0;
  function genId() {
    counter += 1;
    return `evt_${Date.now().toString(36)}_${counter.toString(36)}`;
  }
  function parseStackFrame(nativeError) {
    const stack = new nativeError().stack ?? "";
    const lines = stack.split("\n");
    for (const line of lines) {
      if (!line.includes("@") && !line.includes("at ")) continue;
      if (/payguard|guard-bundle|native code/i.test(line)) continue;
      const trimmed = line.trim();
      const m = trimmed.match(/(https?:\/\/[^\s)]+|\/[^\s)]+\.js[^\s)]*)/);
      return m ? m[1].split(":")[0] === "http" || m[1].startsWith("/") ? shortFrame(m[1]) : trimmed : trimmed;
    }
    return lines[1]?.trim() ?? "unknown";
  }
  function shortFrame(frame) {
    try {
      const u = new URL(frame, location.origin);
      return `${u.pathname}${u.search}@${frame.split("@").pop()?.match(/:\d+:\d+/)?.[0] ?? ""}`.replace(/@$/, "");
    } catch {
      return frame;
    }
  }
  function frameUrl(frame) {
    const m = frame.match(/((?:https?:\/\/)?[^\s@]+\.js[^\s@:]*)/);
    return m ? m[1] : frame;
  }
  function lockProperty(refs, obj, key, value) {
    try {
      refs.defineProperty(obj, key, {
        value,
        writable: false,
        configurable: false,
        enumerable: true
      });
    } catch {
    }
  }
  function disguiseNative(fn, native) {
    try {
      const toString = Function.prototype.toString;
      const nativeStr = toString.call(native);
      Object.defineProperty(fn, "toString", {
        value: () => nativeStr,
        writable: false,
        configurable: false
      });
    } catch {
    }
  }
  function payloadPreview(body, max = 160) {
    const truncated = body.length > max ? `${body.slice(0, max)}\u2026` : body;
    return truncated.replace(/\d[\d -]{11,22}\d/g, (m) => {
      const d = m.replace(/\D/g, "");
      return `****${d.slice(-4)}`;
    });
  }

  // src/guard/core/reporter.ts
  var QUEUE_KEY = "__payguard_pending_events__";
  var Reporter = class {
    constructor(config2, refs) {
      this.config = config2;
      this.refs = refs;
      __publicField(this, "listeners", /* @__PURE__ */ new Set());
      __publicField(this, "queue", []);
      __publicField(this, "flushTimer", null);
      try {
        const raw = window.localStorage.getItem(QUEUE_KEY);
        if (raw) this.queue = JSON.parse(raw);
      } catch {
        this.queue = [];
      }
      window.addEventListener("pagehide", () => this.flush(true), true);
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "hidden") this.flush(true);
      });
    }
    subscribe(fn) {
      this.listeners.add(fn);
      return () => this.listeners.delete(fn);
    }
    emit(partial) {
      const event = { id: genId(), ts: Date.now(), ...partial };
      this.listeners.forEach((fn) => {
        try {
          fn(event);
        } catch {
        }
      });
      if (this.config.debug) {
        console[event.kind === "block" || event.kind === "tamper" ? "warn" : "log"](
          `[PayGuard] ${event.kind}: ${event.detail}`,
          event
        );
      }
      this.queue.push(event);
      this.persist();
      if (!this.flushTimer) {
        this.flushTimer = this.refs.setTimeout(() => this.flush(false), 1500);
      }
      return event;
    }
    persist() {
      try {
        window.localStorage.setItem(QUEUE_KEY, JSON.stringify(this.queue.slice(-50)));
      } catch {
      }
    }
    flush(useBeacon) {
      if (this.queue.length === 0) return;
      const batch = this.queue.splice(0, this.queue.length);
      this.persist();
      if (!this.config.reportEndpoint) return;
      const json = JSON.stringify({ events: batch });
      if (useBeacon && this.refs.sendBeacon) {
        try {
          const ok = this.refs.sendBeacon(this.config.reportEndpoint, json);
          if (ok) return;
        } catch {
        }
      }
      this.refs.fetch(this.config.reportEndpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: json,
        keepalive: true,
        // 内部标记：网络层据此跳过对自身上报的检查
        payguardInternal: true
      }).then(() => {
        if (this.flushTimer) {
          clearTimeout(this.flushTimer);
          this.flushTimer = null;
        }
      }).catch(() => {
        this.queue.unshift(...batch);
        this.persist();
      });
    }
  };

  // src/guard/core/luhn.ts
  function luhnCheck(digits) {
    if (!/^\d{13,19}$/.test(digits)) return false;
    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = digits.charCodeAt(i) - 48;
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }
  function compactDigits(s) {
    return s.replace(/[\s-]/g, "");
  }

  // src/guard/core/scanner.ts
  var SecretScanner = class {
    constructor() {
      __publicField(this, "fingerprints", []);
    }
    register(fp) {
      const exists = this.fingerprints.some(
        (f) => f.exact === fp.exact && f.fieldLabel === fp.fieldLabel
      );
      if (!exists) this.fingerprints.push(fp);
    }
    size() {
      return this.fingerprints.length;
    }
    /** 生成载荷的各种解码候选 */
    candidates(raw) {
      const out = [{ text: raw, via: "plain" }];
      try {
        const urlDecoded = decodeURIComponent(raw);
        if (urlDecoded !== raw) out.push({ text: urlDecoded, via: "url-encoded" });
      } catch {
      }
      const b64Tokens = raw.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [];
      for (const token of b64Tokens) {
        try {
          const decoded = atob(token);
          if (!/^[\x00-\x08]/.test(decoded)) {
            out.push({ text: decoded, via: "base64" });
            try {
              const inner = decodeURIComponent(decoded);
              if (inner !== decoded) out.push({ text: inner, via: "base64+url" });
            } catch {
            }
          }
        } catch {
        }
      }
      return out;
    }
    /**
     * 扫描任意字符串载荷，返回命中的敏感数据。
     */
    scan(raw) {
      if (!raw || raw.length < 3) return [];
      const hits = [];
      const seen = /* @__PURE__ */ new Set();
      const pushHit = (hit) => {
        const key = `${hit.fingerprint.fieldLabel}:${hit.matched}:${hit.via}`;
        if (!seen.has(key)) {
          seen.add(key);
          hits.push(hit);
        }
      };
      for (const cand of this.candidates(raw)) {
        const text = cand.text;
        const panTokens = text.match(/\d(?:\d|[- ]){11,22}\d/g) ?? [];
        const digitRuns = panTokens.map((t) => t.replace(/[ -]/g, ""));
        for (const fp of this.fingerprints) {
          if (fp.exact.length >= 3 && text.includes(fp.exact)) {
            if (fp.fieldLabel === "CVV") {
              const withCard = hits.some((h) => h.fingerprint.dataClass === "payment");
              const withKeyword = /cvv|cvc|security.?code/i.test(text);
              if (!withCard && !withKeyword) continue;
            }
            pushHit({ fingerprint: fp, matched: fp.exact, via: cand.via });
            continue;
          }
          if (fp.compact.length >= 12) {
            const inToken = digitRuns.some((run) => run.includes(fp.compact));
            const inText = text.includes(fp.compact);
            if (inToken || inText) {
              pushHit({ fingerprint: fp, matched: fp.compact, via: `${cand.via}+digit-reassembly` });
              continue;
            }
          }
        }
        for (const pan of panTokens) {
          const digits = compactDigits(pan);
          if (!luhnCheck(digits)) continue;
          const registered = this.fingerprints.find(
            (f) => f.dataClass === "payment" && (f.compact === digits || f.last4 === digits.slice(-4))
          );
          if (registered) {
            pushHit({ fingerprint: registered, matched: digits, via: `${cand.via}+luhn` });
          } else {
            pushHit({
              fingerprint: {
                exact: digits,
                compact: digits,
                last4: digits.slice(-4),
                dataClass: "payment",
                fieldLabel: "\u672A\u767B\u8BB0\u7684\u94F6\u884C\u5361\u53F7"
              },
              matched: digits,
              via: `${cand.via}+luhn-unregistered`
            });
          }
        }
      }
      return hits;
    }
  };

  // src/guard/core/taint.ts
  var TaintRegistry = class {
    constructor() {
      __publicField(this, "records", /* @__PURE__ */ new Map());
      /** 同一服务读同一字段的节流，避免每次 keystroke 都产生事件 */
      __publicField(this, "throttleMs", 4e3);
    }
    noteRead(serviceId, fieldLabel, dataClass, stackFrame) {
      const key = `${serviceId}|${fieldLabel}`;
      const now = Date.now();
      const prev = this.records.get(key);
      if (prev && now - prev.at < this.throttleMs) return null;
      const rec = { serviceId, fieldLabel, dataClass, at: now, stackFrame };
      this.records.set(key, rec);
      return rec;
    }
    /** 某服务读取过的最高敏感等级 */
    maxClassRead(serviceId) {
      let max = null;
      for (const rec of this.records.values()) {
        if (rec.serviceId !== serviceId) continue;
        if (rec.dataClass === "payment") return "payment";
        if (rec.dataClass === "contact") max = "contact";
        else if (!max) max = rec.dataClass;
      }
      return max;
    }
    listByService(serviceId) {
      return [...this.records.values()].filter((r) => r.serviceId === serviceId);
    }
    snapshot() {
      return [...this.records.values()];
    }
  };

  // src/guard/core/services.ts
  var ServiceRegistry = class {
    constructor(services) {
      this.services = services;
    }
    /**
     * 识别 URL 属于哪个服务。
     * @param selfOrigin 当前页面 origin（同源请求归一为 self）
     */
    resolve(url, selfOrigin) {
      let host = "";
      let path = "";
      try {
        const u = new URL(url, selfOrigin);
        host = u.host;
        path = u.pathname;
        if (u.origin === selfOrigin) {
          const byPath2 = this.services.find(
            (s) => s.origins.some((o) => o.startsWith("/") && path.startsWith(o))
          );
          return byPath2 ?? this.services.find((s) => s.id === "self") ?? null;
        }
      } catch {
        host = url;
        path = "";
      }
      const byHost = this.services.find(
        (s) => s.origins.some((o) => {
          if (o.startsWith("/")) return false;
          if (o.startsWith(".")) return host === o.slice(1) || host.endsWith(o);
          return host === o || host.endsWith(`.${o}`);
        })
      );
      if (byHost) return byHost;
      const byPath = this.services.find(
        (s) => s.origins.some((o) => o.startsWith("/") && path.startsWith(o))
      );
      return byPath ?? null;
    }
    get(id) {
      return this.services.find((s) => s.id === id) ?? null;
    }
    all() {
      return this.services;
    }
    /**
     * 脚本加载授权判定（比 resolve 更严格）：
     * 同源 URL 只有命中某个供应商的挂载路径、或显式 self 路径前缀才算授权，
     * 绝不因为"同源"就放行任意路径的脚本（防止 /vendor/unknown 这类注入）。
     */
    isAuthorizedScript(url, selfOrigin, extraPrefixes) {
      if (extraPrefixes.some((p) => url.startsWith(p))) return true;
      let path = url;
      let isSameOrigin = false;
      try {
        const u = new URL(url, selfOrigin);
        path = u.pathname;
        isSameOrigin = u.origin === selfOrigin;
      } catch {
      }
      const pathHit = this.services.some(
        (s) => s.origins.some((o) => o.startsWith("/") && path.startsWith(o))
      );
      if (pathHit) return true;
      if (!isSameOrigin) {
        return this.resolve(url, selfOrigin) !== null;
      }
      return false;
    }
  };

  // src/guard/core/policy.ts
  var CLASS_RANK = { usage: 1, contact: 2, payment: 3 };
  var PolicyEngine = class {
    constructor(services, taint, selfOrigin, blockOnTaint) {
      this.services = services;
      this.taint = taint;
      this.selfOrigin = selfOrigin;
      this.blockOnTaint = blockOnTaint;
    }
    channelAllowed(svc, channel) {
      if (!svc.channels || svc.channels.length === 0) return true;
      return svc.channels.includes(channel);
    }
    pathAllowed(svc, url) {
      if (!svc.pathAllowlist || svc.pathAllowlist.length === 0) return true;
      let path = url;
      try {
        path = new URL(url, this.selfOrigin).pathname + new URL(url, this.selfOrigin).search;
      } catch {
      }
      return svc.pathAllowlist.some((p) => path.includes(p));
    }
    evaluate(req, hits) {
      const target = this.services.resolve(req.url, this.selfOrigin);
      const initiator = this.services.get(req.initiatorService);
      if (hits.length > 0) {
        const maxHit = hits.reduce(
          (a, b) => CLASS_RANK[a.fingerprint.dataClass] >= CLASS_RANK[b.fingerprint.dataClass] ? a : b
        );
        const dc = maxHit.fingerprint.dataClass;
        const targetId = target?.id ?? "unknown";
        const allowed = target !== null && target.dataAllowlist.includes(dc) && this.channelAllowed(target, req.channel) && this.pathAllowed(target, req.url);
        if (allowed) {
          return {
            verdict: "allow",
            detail: `\u76EE\u6807 ${targetId} \u5728\u5141\u8BB8\u540D\u5355\u5185\u63A5\u6536 ${dc} \u6570\u636E\uFF08\u901A\u9053 ${req.channel}\uFF09`,
            hits
          };
        }
        return {
          verdict: "block",
          reason: "sensitive-fingerprint",
          detail: `\u68C0\u51FA${dc === "payment" ? "\u652F\u4ED8" : "\u8054\u7CFB"}\u6570\u636E\uFF08${maxHit.fingerprint.fieldLabel}\uFF0C${maxHit.via}\uFF09\u53D1\u5F80\u672A\u6388\u6743\u76EE\u6807 ${targetId}`,
          hits
        };
      }
      if (target?.trust === "blocked" || initiator?.trust === "blocked") {
        return {
          verdict: "block",
          reason: "blocked-destination",
          detail: `\u670D\u52A1 ${target?.id ?? req.initiatorService} \u5DF2\u88AB\u914D\u7F6E\u4E3A\u7981\u6B62\u5916\u8054`
        };
      }
      const taintedClass = this.taint.maxClassRead(req.initiatorService);
      if (taintedClass) {
        const targetAllowed = target !== null && target.dataAllowlist.includes(taintedClass) && this.channelAllowed(target, req.channel) && this.pathAllowed(target, req.url);
        if (!targetAllowed) {
          return {
            verdict: this.blockOnTaint ? "block" : "report",
            reason: "taint-not-allowed",
            detail: `\u53D1\u8D77\u65B9 ${req.initiatorService} \u8BFB\u53D6\u8FC7 ${taintedClass} \u7EA7\u5B57\u6BB5\uFF0C\u4F46\u76EE\u6807 ${target?.id ?? "unknown"} \u65E0\u6743\u63A5\u6536`
          };
        }
      }
      return { verdict: "allow", detail: "\u65E0\u654F\u611F\u6570\u636E\u3001\u65E0\u6C61\u70B9\u51B2\u7A81" };
    }
  };

  // src/guard/core/field-watcher.ts
  var SENSITIVE_SELECTOR = "input, textarea, select";
  var FieldWatcher = class {
    constructor(config2, scanner) {
      this.config = config2;
      this.scanner = scanner;
      /** element -> 命中的字段定义 */
      __publicField(this, "fieldMap", /* @__PURE__ */ new WeakMap());
      __publicField(this, "known", /* @__PURE__ */ new Set());
      this.scanAll();
      new MutationObserver((mutations) => {
        for (const m of mutations) {
          m.addedNodes.forEach((node) => {
            if (node instanceof Element) {
              if (node.matches?.(SENSITIVE_SELECTOR)) this.inspect(node);
              node.querySelectorAll?.(SENSITIVE_SELECTOR).forEach((el) => this.inspect(el));
            }
          });
        }
      }).observe(document.documentElement, { childList: true, subtree: true });
    }
    classify(el) {
      if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement)) {
        return null;
      }
      const haystack = [
        el.getAttribute("name") ?? "",
        el.id,
        el.getAttribute("autocomplete") ?? "",
        el.getAttribute("data-pg") ?? "",
        el.getAttribute("aria-label") ?? "",
        el.getAttribute("placeholder") ?? ""
      ].join(" ").toLowerCase();
      const hit = this.config.sensitiveFields.find(
        (def) => def.match.some((token) => {
          const t = token.toLowerCase();
          if (/[一-鿿]/.test(t)) return haystack.includes(t);
          return new RegExp(`(^|[^a-z0-9])${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9]|$)`).test(haystack);
        })
      );
      return hit ?? null;
    }
    scanAll() {
      document.querySelectorAll(SENSITIVE_SELECTOR).forEach((el) => this.inspect(el));
    }
    inspect(el) {
      if (this.known.has(el)) return;
      const def = this.classify(el);
      if (!def) return;
      this.known.add(el);
      this.fieldMap.set(el, def);
      el.setAttribute("data-pg-watched", def.dataClass);
      el.addEventListener(
        "input",
        () => this.registerValue(el, def),
        true
      );
      el.addEventListener(
        "change",
        () => this.registerValue(el, def),
        true
      );
      const v = el.value;
      if (v) this.registerValue(el, def);
    }
    getFieldDef(el) {
      return this.fieldMap.get(el) ?? this.classify(el);
    }
    registerValue(el, def) {
      const raw = el.value?.trim();
      if (!raw) return;
      const fp = {
        exact: raw,
        compact: compactDigits(raw),
        dataClass: def.dataClass,
        fieldLabel: def.label
      };
      if (def.dataClass === "payment" && def.label.includes("\u5361\u53F7")) {
        const digits = compactDigits(raw);
        if (!luhnCheck(digits)) return;
        fp.last4 = digits.slice(-4);
      }
      if (def.label === "CVV" && !/^\d{3,4}$/.test(raw)) return;
      if (def.dataClass === "contact" && raw.length < 3) return;
      this.scanner.register(fp);
    }
  };

  // src/guard/hooks/network-hooks.ts
  var INTERNAL_KEY = "payguardInternal";
  function isSameOriginUrl(rawUrl, pageOrigin) {
    try {
      const u = new URL(rawUrl, pageOrigin);
      const page = new URL(pageOrigin);
      return u.host === page.host && u.protocol.replace("ws", "http") === page.protocol;
    } catch {
      return false;
    }
  }
  function extractUrl(input, init) {
    let url = "";
    let method = "GET";
    let body = "";
    if (typeof input === "string") {
      url = input;
      method = init?.method ?? "GET";
      body = bodyToString(init?.body);
    } else if (input instanceof Request) {
      url = input.url;
      method = init?.method ?? input.method;
      body = init?.body ? bodyToString(init.body) : "[request-stream]";
    }
    return { url, method: method.toUpperCase(), body };
  }
  function bodyToString(body) {
    if (body == null) return "";
    if (typeof body === "string") return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      const parts = [];
      body.forEach((v, k) => parts.push(`${k}=${typeof v === "string" ? v : "[file]"}`));
      return parts.join("&");
    }
    if (body instanceof Blob) return "[blob]";
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return "[binary]";
    return String(body);
  }
  function installNetworkHooks(api) {
    const refs = api.refs;
    const { fetch: nativeFetch, XMLHttpRequest: NativeXHR, sendBeacon: nativeBeacon } = refs;
    const hookedFetch = function(input, init) {
      if (init?.[INTERNAL_KEY] === true || input instanceof Request && input[INTERNAL_KEY]) {
        return nativeFetch(input, init);
      }
      const frame = parseStackFrame(refs.Error);
      const req = extractUrl(input, init);
      const decision = api.inspectOutbound(
        { url: req.url, channel: "fetch", method: req.method, body: req.body },
        frame
      );
      if (decision.verdict === "block") {
        return fakeBlockedResponse(req.url);
      }
      const p = nativeFetch(input, init);
      if (req.body === "[request-stream]" && typeof input !== "string") {
        input.clone().text().then((text) => {
          const d2 = api.inspectOutbound(
            { url: req.url, channel: "fetch", method: req.method, body: text },
            frame
          );
          if (d2.verdict === "block") {
            p.then((r) => r.body?.cancel()).catch(() => void 0);
          }
        }).catch(() => void 0);
      }
      return p;
    };
    disguiseNative(hookedFetch, nativeFetch);
    lockProperty(refs, window, "fetch", hookedFetch);
    class HookedXHR extends NativeXHR {
      constructor() {
        super(...arguments);
        __publicField(this, "pgUrl", "");
        __publicField(this, "pgMethod", "GET");
        __publicField(this, "pgFrame", "");
      }
      open(method, url, ...rest) {
        this.pgMethod = method;
        this.pgUrl = String(url);
        this.pgFrame = parseStackFrame(refs.Error);
        return super.open(method, url, ...rest);
      }
      send(body) {
        const decision = api.inspectOutbound(
          {
            url: this.pgUrl,
            channel: "xhr",
            method: this.pgMethod,
            body: bodyToString(body ?? null)
          },
          this.pgFrame
        );
        if (decision.verdict === "block") {
          this.simulateBlocked();
          return;
        }
        return super.send(body);
      }
      simulateBlocked() {
        const self = this;
        refs.setTimeout(() => {
          Object.defineProperty(self, "readyState", { value: 4, configurable: true });
          Object.defineProperty(self, "status", { value: 204, configurable: true });
          Object.defineProperty(self, "statusText", { value: "No Content", configurable: true });
          Object.defineProperty(self, "responseText", { value: "", configurable: true });
          Object.defineProperty(self, "response", { value: "", configurable: true });
          try {
            self.dispatchEvent(new Event("readystatechange"));
            self.dispatchEvent(new ProgressEvent("load", { total: 0, loaded: 0 }));
            self.dispatchEvent(new ProgressEvent("loadend", { total: 0, loaded: 0 }));
          } catch {
          }
        }, 0);
      }
    }
    disguiseNative(HookedXHR, NativeXHR);
    lockProperty(refs, window, "XMLHttpRequest", HookedXHR);
    if (nativeBeacon) {
      const hookedBeacon = function(url, data) {
        const frame = parseStackFrame(refs.Error);
        const decision = api.inspectOutbound(
          { url: String(url), channel: "beacon", method: "POST", body: bodyToString(data ?? null) },
          frame
        );
        if (decision.verdict === "block") return true;
        return nativeBeacon(url, data);
      };
      disguiseNative(hookedBeacon, nativeBeacon);
      lockProperty(refs, navigator, "sendBeacon", hookedBeacon);
    }
    const NativeWS = window.WebSocket;
    if (NativeWS) {
      class HookedWS extends NativeWS {
        constructor(url, protocols) {
          const frame = parseStackFrame(refs.Error);
          const isSameOrigin = isSameOriginUrl(String(url), api.origin);
          const decision = isSameOrigin ? { verdict: "allow" } : api.inspectOutbound(
            { url: String(url), channel: "websocket", method: "WS", body: "" },
            frame
          );
          if (decision.verdict === "block") {
            super("ws://127.0.0.1:0/__payguard_blocked__");
            refs.setTimeout(() => this.close(), 0);
            return;
          }
          super(url, protocols);
          this.addEventListener("open", () => {
            const nativeSend = this.send.bind(this);
            try {
              refs.defineProperty(this, "send", {
                value: (data) => {
                  const d = api.inspectOutbound(
                    { url: String(url), channel: "websocket", method: "WS-MSG", body: typeof data === "string" ? data : "[binary]" },
                    frame
                  );
                  if (d.verdict !== "block") nativeSend(data);
                },
                writable: false,
                configurable: false
              });
            } catch {
            }
          });
        }
      }
      disguiseNative(HookedWS, NativeWS);
      lockProperty(refs, window, "WebSocket", HookedWS);
    }
    const NativeES = window.EventSource;
    if (NativeES) {
      class HookedES extends NativeES {
        constructor(url, config2) {
          const frame = parseStackFrame(refs.Error);
          const isSameOrigin = isSameOriginUrl(String(url), api.origin);
          const decision = isSameOrigin ? { verdict: "allow" } : api.inspectOutbound(
            { url: String(url), channel: "eventsource", method: "GET", body: "" },
            frame
          );
          if (decision.verdict === "block") {
            super("about:blank");
            refs.setTimeout(() => this.close(), 0);
            return;
          }
          super(url, config2);
        }
      }
      disguiseNative(HookedES, NativeES);
      lockProperty(refs, window, "EventSource", HookedES);
    }
  }
  function fakeBlockedResponse(url) {
    const p = Promise.resolve(new Response(null, {
      status: 204,
      statusText: "No Content",
      headers: { "x-payguard": "blocked" }
    }));
    return p.then((r) => {
      try {
        Object.defineProperty(r, "url", { value: url, configurable: true });
      } catch {
      }
      return r;
    });
  }

  // src/guard/hooks/dom-hooks.ts
  var silent = false;
  function runSilent(fn) {
    const prev = silent;
    silent = true;
    try {
      return fn();
    } finally {
      silent = prev;
    }
  }
  function installDomHooks(api) {
    const refs = api.refs;
    const d = refs.getOwnPropertyDescriptor;
    const wrapValueGetter = (proto, name = "value") => {
      const desc = d(proto, name);
      if (!desc?.get) return;
      const nativeGet = desc.get;
      const nativeSet = desc.set;
      refs.defineProperty(proto, name, {
        get() {
          const val = nativeGet.call(this);
          if (!silent && this instanceof Element && api.isWatchedField(this)) {
            api.noteSensitiveRead(this, parseStackFrame(refs.Error));
          }
          return val;
        },
        set(v) {
          nativeSet?.call(this, v);
        },
        configurable: false,
        enumerable: desc.enumerable
      });
    };
    wrapValueGetter(HTMLInputElement.prototype);
    wrapValueGetter(HTMLTextAreaElement.prototype);
    wrapValueGetter(HTMLSelectElement.prototype);
    const attrDesc = d(Element.prototype, "getAttribute");
    const nativeGetAttr = attrDesc?.value;
    if (nativeGetAttr) {
      refs.defineProperty(Element.prototype, "getAttribute", {
        value: function(name) {
          const ret = nativeGetAttr.call(this, name);
          if (!silent && this instanceof Element && api.isWatchedField(this) && name.toLowerCase() === "value" && ret != null) {
            api.noteSensitiveRead(this, parseStackFrame(refs.Error));
          }
          return ret;
        },
        writable: false,
        configurable: false
      });
    }
  }

  // src/guard/hooks/resource-hooks.ts
  function installResourceHooks(api) {
    const refs = api.refs;
    const d = refs.getOwnPropertyDescriptor;
    const checkUrl = (url, channel, body = "") => api.inspectOutbound({ url, channel, method: "GET", body }, parseStackFrame(refs.Error));
    const wrapAttr = (proto, attr, channel) => {
      const desc = d(proto, attr);
      if (!desc?.set) return;
      const nativeSet = desc.set;
      const nativeGet = desc.get;
      refs.defineProperty(proto, attr, {
        get() {
          return nativeGet?.call(this);
        },
        set(v) {
          const decision = checkUrl(String(v), channel);
          if (decision.verdict === "block") {
            nativeSet.call(this, TRANSPARENT_PIXEL);
            return;
          }
          nativeSet.call(this, v);
        },
        configurable: false,
        enumerable: desc.enumerable
      });
    };
    wrapAttr(HTMLImageElement.prototype, "src", "image");
    wrapAttr(HTMLImageElement.prototype, "srcset", "image");
    const nativeSetAttr = Element.prototype.setAttribute;
    refs.defineProperty(Element.prototype, "setAttribute", {
      value: function(name, value) {
        const lower = name.toLowerCase();
        const isImg = this instanceof HTMLImageElement && (lower === "src" || lower === "srcset");
        const isLink = this instanceof HTMLLinkElement && lower === "href";
        if (isImg || isLink) {
          let channel = "image";
          if (isLink) {
            const link = this;
            channel = link.rel === "preload" && /font/i.test(link.as) ? "font" : "css";
          }
          const decision = checkUrl(String(value), channel);
          if (decision.verdict === "block") {
            nativeSetAttr.call(this, name, isImg ? TRANSPARENT_PIXEL : "about:blank");
            return;
          }
        }
        return nativeSetAttr.call(this, name, value);
      },
      writable: false,
      configurable: false
    });
    const NativeFontFace = window.FontFace;
    if (NativeFontFace) {
      const HookedFontFace = function(family, source, desc) {
        if (typeof source === "string") {
          const urls = source.match(/url\((['"]?)([^'")]+)\1\)/g) ?? [];
          for (const u of urls) {
            const m = u.match(/url\(['"]?([^'")]+)['"]?\)/);
            if (m) {
              const decision = checkUrl(m[1], "font", source);
              if (decision.verdict === "block") {
                return new NativeFontFace(family, `url(${EMPTY_FONT})`, desc);
              }
            }
          }
        }
        return new NativeFontFace(family, source, desc);
      };
      refs.defineProperty(window, "FontFace", {
        value: HookedFontFace,
        writable: false,
        configurable: false
      });
    }
    if (HTMLLinkElement.prototype) {
      const linkDesc = d(HTMLLinkElement.prototype, "href");
      if (linkDesc?.set) {
        const nativeSet = linkDesc.set;
        refs.defineProperty(HTMLLinkElement.prototype, "href", {
          get() {
            return linkDesc.get?.call(this);
          },
          set(v) {
            const rel = this.rel?.toLowerCase() ?? "";
            const isFont = rel === "preload" && /font/i.test(this.as ?? "");
            const channel = isFont ? "font" : "css";
            const decision = checkUrl(String(v), channel);
            if (decision.verdict === "block") {
              nativeSet.call(this, "about:blank");
              return;
            }
            nativeSet.call(this, v);
          },
          configurable: false,
          enumerable: linkDesc.enumerable
        });
      }
    }
    const cssUrlPattern = /url\((['"]?)(https?:)?\/\/[^'")]+\1\)/;
    const urlExtract = /url\(['"]?([^'")]+)['"]?\)/;
    const styleDesc = d(HTMLElement.prototype, "style");
    const nativeStyleGet = styleDesc?.get;
    if (nativeStyleGet) {
      const nativeSetProperty = CSSStyleDeclaration.prototype.setProperty;
      refs.defineProperty(CSSStyleDeclaration.prototype, "setProperty", {
        value: function(prop, value, priority) {
          if (typeof value === "string" && cssUrlPattern.test(value)) {
            const m = value.match(urlExtract);
            if (m) {
              const decision = checkUrl(m[1], "css", value);
              if (decision.verdict === "block") {
                nativeSetProperty.call(this, prop, "none", priority);
                return;
              }
            }
          }
          return nativeSetProperty.call(this, prop, value, priority);
        },
        writable: false,
        configurable: false
      });
    }
    const anchorDesc = d(HTMLAnchorElement.prototype, "href");
    if (anchorDesc?.set) {
      const nativeAnchorSet = anchorDesc.set;
      refs.defineProperty(HTMLAnchorElement.prototype, "href", {
        get() {
          return anchorDesc.get?.call(this);
        },
        set(v) {
          const decision = checkUrl(String(v), "link");
          if (decision.verdict === "block") {
            nativeAnchorSet.call(this, "about:blank#blocked-by-payguard");
            return;
          }
          nativeAnchorSet.call(this, v);
        },
        configurable: false,
        enumerable: anchorDesc.enumerable
      });
    }
  }
  var TRANSPARENT_PIXEL = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
  var EMPTY_FONT = "data:font/woff2;base64,d09GMgABAAAAAAEwAA";

  // src/guard/hooks/nav-hooks.ts
  function installNavHooks(api) {
    const refs = api.refs;
    const check = (url) => api.inspectOutbound(
      { url, channel: "navigation", method: "GET", body: "" },
      parseStackFrame(refs.Error)
    );
    const nativeOpen = window.open;
    const hookedOpen = function(url, ...rest) {
      if (url) {
        const decision = check(String(url));
        if (decision.verdict === "block") return null;
      }
      return nativeOpen.call(window, url, ...rest);
    };
    disguiseNative(hookedOpen, nativeOpen);
    lockProperty(refs, window, "open", hookedOpen);
    const nativeAssign = location.assign.bind(location);
    const nativeReplace = location.replace.bind(location);
    const canWrap = (obj, name) => {
      const d = Object.getOwnPropertyDescriptor(obj, name);
      return !d || d.configurable === true;
    };
    const wrapLoc = (name, native) => {
      const wrapper = (url) => {
        const decision = check(String(url));
        if (decision.verdict === "block") return;
        native(String(url));
      };
      if (canWrap(location, name)) {
        try {
          refs.defineProperty(location, name, {
            value: wrapper,
            writable: false,
            configurable: false
          });
          return;
        } catch {
        }
      }
      if (canWrap(Location.prototype, name)) {
        try {
          refs.defineProperty(Location.prototype, name, {
            value: wrapper,
            writable: false,
            configurable: false
          });
        } catch {
        }
      }
    };
    wrapLoc("assign", nativeAssign);
    wrapLoc("replace", nativeReplace);
    const locDesc = refs.getOwnPropertyDescriptor(Location.prototype, "href");
    if (locDesc?.set) {
      const nativeSet = locDesc.set;
      refs.defineProperty(Location.prototype, "href", {
        get() {
          return locDesc.get?.call(this);
        },
        set(v) {
          const decision = check(String(v));
          if (decision.verdict === "block") return;
          nativeSet.call(this, v);
        },
        configurable: false,
        enumerable: locDesc.enumerable
      });
    }
  }

  // src/guard/hooks/script-hooks.ts
  function installScriptHooks(api, gate) {
    const refs = api.refs;
    const d = refs.getOwnPropertyDescriptor;
    const blockScript = (script, reason, detail) => {
      api.reporter.emit({
        kind: reason === "integrity-mismatch" ? "tamper" : "block",
        channel: "script-load",
        reason,
        serviceId: api.identifyInitiator(parseStackFrame(refs.Error)),
        targetUrl: script.src,
        detail,
        stackFrame: parseStackFrame(refs.Error)
      });
      try {
        if (script.src !== "about:blank") script.src = "about:blank";
        script.remove();
      } catch {
      }
    };
    const blockedNodes = /* @__PURE__ */ new WeakSet();
    const srcDesc = d(HTMLScriptElement.prototype, "src");
    if (srcDesc?.set) {
      const nativeSet = srcDesc.set;
      refs.defineProperty(HTMLScriptElement.prototype, "src", {
        get() {
          return srcDesc.get?.call(this);
        },
        set(v) {
          const url = String(v);
          const result = gate.checkScriptUrl(url);
          if (!result.ok) {
            blockedNodes.add(this);
            blockScript(this, "unauthorized-script", result.detail ?? url);
            nativeSet.call(this, "about:blank");
            return;
          }
          nativeSet.call(this, v);
          const normalized = url.replace("/_tampered", "");
          const protectedScript = api.config.protectedScripts?.find(
            (p) => normalized.includes(new URL(p.src, location.origin).pathname)
          );
          if (protectedScript) {
            gate.verifyIntegrity(url, protectedScript.integrity).then((ok) => {
              if (!ok) {
                blockScript(this, "integrity-mismatch", `SRI \u6821\u9A8C\u5931\u8D25\uFF0C\u811A\u672C\u7591\u4F3C\u88AB\u7BE1\u6539\uFF1A${url}`);
              }
            });
          }
        },
        configurable: false,
        enumerable: srcDesc.enumerable
      });
    }
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        m.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLScriptElement) || !node.src) return;
          if (node.src === "about:blank" || blockedNodes.has(node)) return;
          const result = gate.checkScriptUrl(node.src);
          if (!result.ok) {
            blockedNodes.add(node);
            blockScript(node, "unauthorized-script", result.detail ?? node.src);
          }
        });
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

  // src/guard/hooks/tamper-hooks.ts
  var HOOK_KEYS = /* @__PURE__ */ new Set(["fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "FontFace"]);
  function installTamperHooks(api, snapshotProvider) {
    const refs = api.refs;
    const ownListeners = /* @__PURE__ */ new WeakSet();
    api.markOwnListener = (fn) => ownListeners.add(fn);
    api.isOwnListener = (fn) => ownListeners.has(fn);
    const frame = () => {
      try {
        return new refs.Error().stack?.split("\n")[2]?.trim() ?? "unknown";
      } catch {
        return "unknown";
      }
    };
    const nativeDefine = Object.defineProperty;
    const hookedDefine = function(obj, key, desc) {
      const keyStr = String(key);
      const isHookTarget = (obj === window || obj === navigator || obj === Object.prototype || obj === EventTarget.prototype) && (HOOK_KEYS.has(keyStr) || keyStr === "defineProperty" || keyStr === "removeEventListener");
      if (isHookTarget) {
        api.reportTamper(`\u68C0\u6D4B\u5230\u5BF9\u53D7\u4FDD\u62A4 API ${keyStr} \u7684 defineProperty \u91CD\u5199\u5C1D\u8BD5`, frame());
        return obj;
      }
      return nativeDefine(obj, key, desc);
    };
    lockProperty(refs, Object, "defineProperty", hookedDefine);
    const nativeReflectDefine = Reflect.defineProperty;
    refs.defineProperty(Reflect, "defineProperty", {
      value: (target, key, desc) => {
        const keyStr = String(key);
        if (target === window && HOOK_KEYS.has(keyStr)) {
          api.reportTamper(`\u68C0\u6D4B\u5230\u901A\u8FC7 Reflect.defineProperty \u91CD\u5199 ${keyStr} \u7684\u5C1D\u8BD5`, frame());
          return true;
        }
        return nativeReflectDefine(target, key, desc);
      },
      writable: false,
      configurable: false
    });
    const nativeDelete = Reflect.deleteProperty;
    refs.defineProperty(Reflect, "deleteProperty", {
      value: (target, key) => {
        const keyStr = String(key);
        if (target === window && HOOK_KEYS.has(keyStr)) {
          api.reportTamper(`\u68C0\u6D4B\u5230\u5220\u9664\u53D7\u4FDD\u62A4 API ${keyStr} \u7684\u5C1D\u8BD5`, frame());
          return false;
        }
        return nativeDelete(target, key);
      },
      writable: false,
      configurable: false
    });
    const nativeRemove = EventTarget.prototype.removeEventListener;
    refs.defineProperty(EventTarget.prototype, "removeEventListener", {
      value: function(type, fn, ...rest) {
        if (fn && api.isOwnListener(fn)) {
          api.reportTamper(`\u68C0\u6D4B\u5230\u8BD5\u56FE\u79FB\u9664 PayGuard \u7684 ${type} \u76D1\u542C\u5668`, frame());
          return;
        }
        return nativeRemove.call(this, type, fn, ...rest);
      },
      writable: false,
      configurable: false
    });
    const guardScript = document.currentScript;
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        m.removedNodes.forEach((node) => {
          if (node === guardScript || node instanceof HTMLScriptElement && /guard-bundle/.test(node.src)) {
            api.reportTamper("\u68C0\u6D4B\u5230 PayGuard \u811A\u672C\u6807\u7B7E\u88AB\u79FB\u9664\uFF08\u94A9\u5B50\u4ECD\u5728\u5185\u5B58\u4E2D\u8FD0\u884C\uFF09", frame());
          }
        });
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
    let snapshots = null;
    const heartbeat = refs.setInterval(() => {
      if (!snapshots) snapshots = snapshotProvider();
      for (const snap of snapshots) {
        const desc = refs.getOwnPropertyDescriptor(snap.obj, snap.key);
        if (!desc) {
          api.reportTamper(`\u5FC3\u8DF3\u6821\u9A8C\uFF1A${snap.label} \u63CF\u8FF0\u7B26\u6D88\u5931`, frame());
          continue;
        }
        const current = "value" in desc ? desc.value : desc.get;
        if (current !== snap.expected) {
          api.reportTamper(`\u5FC3\u8DF3\u6821\u9A8C\uFF1A${snap.label} \u5DF2\u88AB\u66FF\u6362\u4E3A\u5916\u90E8\u5B9E\u73B0`, frame());
        }
        if (desc.writable || desc.configurable) {
          api.reportTamper(`\u5FC3\u8DF3\u6821\u9A8C\uFF1A${snap.label} \u9501\u5B9A\u72B6\u6001\u88AB\u7834\u574F`, frame());
        }
      }
    }, api.config.heartbeatMs);
    return () => clearInterval(heartbeat);
  }

  // src/guard/guard.ts
  var Guard = class {
    constructor(config2) {
      __publicField(this, "config");
      __publicField(this, "refs", captureNatives());
      __publicField(this, "reporter");
      __publicField(this, "origin");
      __publicField(this, "scanner", new SecretScanner());
      __publicField(this, "taint", new TaintRegistry());
      __publicField(this, "services");
      __publicField(this, "policy");
      __publicField(this, "fields");
      __publicField(this, "stopHeartbeat", null);
      __publicField(this, "ownListenerSet", /* @__PURE__ */ new WeakSet());
      this.config = config2;
      this.origin = window.location.origin;
      this.reporter = new Reporter(config2, this.refs);
      this.services = new ServiceRegistry(config2.services);
      this.policy = new PolicyEngine(this.services, this.taint, this.origin, config2.blockOnTaint);
      this.fields = new FieldWatcher(config2, this.scanner);
    }
    // ---------- GuardApi ----------
    identifyInitiator(stackFrame) {
      const url = frameUrl(stackFrame);
      const svc = this.services.resolve(url, this.origin);
      return svc?.id ?? "unknown";
    }
    inspectOutbound(input, stackFrame) {
      const initiatorService = this.identifyInitiator(stackFrame);
      const combined = `${input.url}
${input.body}`;
      const hits = this.scanner.scan(combined);
      const decision = this.policy.evaluate(
        {
          url: input.url,
          channel: input.channel,
          method: input.method,
          body: input.body,
          stackFrame,
          initiatorService
        },
        hits
      );
      if (decision.verdict === "block") {
        this.reporter.emit({
          kind: "block",
          channel: input.channel,
          reason: decision.reason,
          serviceId: initiatorService,
          targetUrl: input.url,
          dataClass: hits[0]?.fingerprint.dataClass,
          fieldLabel: hits[0]?.fingerprint.fieldLabel,
          detail: decision.detail,
          stackFrame,
          payloadPreview: input.body ? payloadPreview(input.body) : void 0
        });
      } else if (decision.verdict === "report") {
        this.reporter.emit({
          kind: "alert",
          channel: input.channel,
          reason: decision.reason,
          serviceId: initiatorService,
          targetUrl: input.url,
          detail: decision.detail,
          stackFrame
        });
      }
      return decision;
    }
    noteSensitiveRead(el, stackFrame) {
      const def = this.fields.getFieldDef(el);
      if (!def) return;
      const serviceId = this.identifyInitiator(stackFrame);
      const rec = this.taint.noteRead(serviceId, def.label, def.dataClass, stackFrame);
      if (rec) {
        this.reporter.emit({
          kind: "observation",
          serviceId,
          fieldLabel: def.label,
          dataClass: def.dataClass,
          detail: `\u670D\u52A1 ${serviceId} \u8BFB\u53D6\u4E86\u654F\u611F\u5B57\u6BB5\u300C${def.label}\u300D`,
          stackFrame
        });
      }
    }
    isWatchedField(el) {
      return runSilent(() => this.fields.getFieldDef(el) !== null);
    }
    markOwnListener(fn) {
      this.ownListenerSet.add(fn);
    }
    isOwnListener(fn) {
      return this.ownListenerSet.has(fn);
    }
    reportTamper(detail, stackFrame) {
      return this.reporter.emit({
        kind: "tamper",
        reason: "guard-tamper",
        serviceId: this.identifyInitiator(stackFrame),
        detail,
        stackFrame
      });
    }
    // ---------- ScriptGate ----------
    checkScriptUrl(url) {
      if (!/^https?:\/\//.test(url) && !url.startsWith("/")) return { ok: true };
      const extra = this.config.extraAllowedScriptPrefixes ?? [];
      if (url.includes("/_tampered/")) {
        const normalized = url.replace("/_tampered", "");
        const protectedMatch = this.config.protectedScripts?.some(
          (p) => normalized.includes(new URL(p.src, this.origin).pathname)
        );
        if (protectedMatch) return { ok: true };
      }
      const authorized = this.services.isAuthorizedScript(url, this.origin, extra);
      if (!authorized) {
        return {
          ok: false,
          reason: "unauthorized-script",
          detail: `\u811A\u672C\u4E0D\u5728\u4F9B\u5E94\u5546\u5141\u8BB8\u540D\u5355\u5185\uFF1A${url}`
        };
      }
      return { ok: true };
    }
    async verifyIntegrity(src, expected) {
      try {
        const res = await this.refs.fetch(src, { cache: "no-store" });
        const buf = await res.arrayBuffer();
        const hash = await crypto.subtle.digest("SHA-384", buf);
        const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
        return expected === `sha384-${base64}`;
      } catch {
        return true;
      }
    }
    // ---------- 安装 ----------
    install() {
      const steps = [
        ["dom", () => installDomHooks(this)],
        ["network", () => installNetworkHooks(this)],
        ["resource", () => installResourceHooks(this)],
        ["nav", () => installNavHooks(this)],
        ["script", () => installScriptHooks(this, this)],
        [
          "tamper",
          () => {
            this.stopHeartbeat = installTamperHooks(this, () => this.collectSnapshots());
          }
        ]
      ];
      for (const [name, step] of steps) {
        try {
          step();
        } catch (err) {
          this.reporter.emit({
            kind: "tamper",
            reason: "guard-tamper",
            serviceId: "self",
            detail: `\u9632\u62A4\u5C42 ${name} \u5B89\u88C5\u5F02\u5E38\uFF08\u5DF2\u964D\u7EA7\uFF0C\u5176\u4F59\u901A\u9053\u4ECD\u751F\u6548\uFF09\uFF1A${err.message}`,
            stackFrame: "install"
          });
        }
      }
      this.reporter.emit({
        kind: "observation",
        serviceId: "self",
        detail: `PayGuard \u5DF2\u542F\u52A8\uFF0C\u76D1\u63A7 ${this.config.services.length} \u4E2A\u670D\u52A1\u914D\u7F6E\u3001${this.collectSnapshots().length} \u4E2A\u53D7\u4FDD\u62A4 API`,
        stackFrame: "boot"
      });
    }
    collectSnapshots() {
      const get = (obj, key) => ({
        label: key,
        obj,
        key,
        expected: obj[key]
      });
      const snaps = [
        get(window, "fetch"),
        get(window, "XMLHttpRequest"),
        get(window, "WebSocket"),
        get(window, "EventSource"),
        get(window, "FontFace"),
        get(navigator, "sendBeacon"),
        get(Object, "defineProperty"),
        get(EventTarget.prototype, "removeEventListener"),
        get(Element.prototype, "setAttribute")
      ];
      const vd = this.refs.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
      if (vd?.get) {
        snaps.push({ label: "input.value getter", obj: HTMLInputElement.prototype, key: "value", expected: vd.get });
      }
      return snaps.filter((s) => s.expected != null);
    }
    /** 供演示面板使用的调试 API（挂在 window.__PAYGUARD__，不可枚举） */
    debugApi() {
      return {
        config: this.config,
        subscribe: (fn) => this.reporter.subscribe(fn),
        taint: () => this.taint.snapshot(),
        services: () => this.services.all(),
        fingerprints: () => this.scanner.size()
      };
    }
  };

  // src/guard/main.ts
  var config = window.__PAYGUARD_CONFIG__;
  if (!config) {
    console.error("[PayGuard] \u7F3A\u5C11 window.__PAYGUARD_CONFIG__\uFF0C\u9632\u62A4\u672A\u542F\u52A8");
  } else {
    const guard = new Guard(config);
    guard.install();
    try {
      Object.defineProperty(window, "__PAYGUARD__", {
        value: guard.debugApi(),
        writable: false,
        configurable: false,
        enumerable: false
        // 对简单枚举探针隐藏
      });
    } catch {
    }
  }
})();
//# sourceMappingURL=guard-bundle.js.map
