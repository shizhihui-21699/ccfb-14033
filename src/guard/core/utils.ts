/**
 * 通用工具：原生函数保管、调用栈解析、钩子锁定、id 生成
 */

export type AnyFn = (...args: unknown[]) => unknown;

/** 保管原生引用 —— 所有内部上报都走这些快照，防止攻击者事后替换 window.fetch */
export interface NativeRefs {
  fetch: typeof fetch;
  XMLHttpRequest: typeof XMLHttpRequest;
  sendBeacon: Navigator['sendBeacon'];
  defineProperty: typeof Object.defineProperty;
  getOwnPropertyDescriptor: typeof Object.getOwnPropertyDescriptor;
  Proxy: typeof Proxy;
  Reflect: typeof Reflect;
  Error: typeof Error;
  atob: typeof atob;
  setTimeout: typeof setTimeout;
  setInterval: typeof setInterval;
}

export function captureNatives(): NativeRefs {
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
    setInterval: window.setInterval.bind(window),
  };
}

let counter = 0;
export function genId(): string {
  counter += 1;
  return `evt_${Date.now().toString(36)}_${counter.toString(36)}`;
}

/**
 * 从调用栈中找出第一个不属于 PayGuard 自身、也不属于浏览器原生的帧，
 * 用来回答"是哪个脚本干的"。
 */
export function parseStackFrame(nativeError: typeof Error): string {
  const stack = new nativeError().stack ?? '';
  const lines = stack.split('\n');
  for (const line of lines) {
    if (!line.includes('@') && !line.includes('at ')) continue;
    if (/payguard|guard-bundle|native code/i.test(line)) continue;
    const trimmed = line.trim();
    // 提取 URL:line:col
    const m = trimmed.match(/(https?:\/\/[^\s)]+|\/[^\s)]+\.js[^\s)]*)/);
    return m ? m[1].split(':')[0] === 'http' || m[1].startsWith('/') ? shortFrame(m[1]) : trimmed : trimmed;
  }
  return lines[1]?.trim() ?? 'unknown';
}

function shortFrame(frame: string): string {
  try {
    const u = new URL(frame, location.origin);
    return `${u.pathname}${u.search}@${frame.split('@').pop()?.match(/:\d+:\d+/)?.[0] ?? ''}`.replace(/@$/, '');
  } catch {
    return frame;
  }
}

/** 从帧 URL 推断发起方服务（交给 ServiceRegistry 做最终判定） */
export function frameUrl(frame: string): string {
  const m = frame.match(/((?:https?:\/\/)?[^\s@]+\.js[^\s@:]*)/);
  return m ? m[1] : frame;
}

/**
 * 用不可写、不可配置的描述符安装钩子，使外部无法重新赋值或 delete。
 * 注意：configurable:false 后我们自己也不能再改，所以一次性装好。
 */
export function lockProperty(
  refs: NativeRefs,
  obj: object,
  key: string | symbol,
  value: unknown,
): void {
  try {
    refs.defineProperty(obj, key, {
      value,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  } catch {
    /* 属性已被锁定等极端情况，忽略 */
  }
}

/** 让被包装的原生函数在 toString 时看起来仍是 native，规避简单探针 */
export function disguiseNative(fn: AnyFn, native: AnyFn): void {
  try {
    const toString = Function.prototype.toString;
    const nativeStr = toString.call(native);
    Object.defineProperty(fn, 'toString', {
      value: () => nativeStr,
      writable: false,
      configurable: false,
    });
  } catch {
    /* ignore */
  }
}

/** 生成载荷预览：截断 + 不允许出现完整连续卡号 */
export function payloadPreview(body: string, max = 160): string {
  const truncated = body.length > max ? `${body.slice(0, max)}…` : body;
  return truncated.replace(/\d[\d -]{11,22}\d/g, (m) => {
    const d = m.replace(/\D/g, '');
    return `****${d.slice(-4)}`;
  });
}
