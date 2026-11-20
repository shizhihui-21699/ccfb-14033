/**
 * network-hooks —— 网络外发通道拦截
 * fetch / XMLHttpRequest / navigator.sendBeacon / WebSocket / EventSource
 *
 * 所有拦截都在"真正发出字节之前"完成判定，阻断时构造符合 API 契约的
 * 假响应/假对象，让恶意脚本以为请求成功了，从而不会立刻发现防护存在。
 */
import type { GuardApi, OutboundInput } from '../context';
import type { NativeRefs } from '../core/utils';
import { disguiseNative, lockProperty, parseStackFrame } from '../core/utils';

type AnyFn = (...args: unknown[]) => unknown;
const INTERNAL_KEY = 'payguardInternal';

/** 判断 url 是否与页面同源（兼容 ws/wss 与相对路径） */
function isSameOriginUrl(rawUrl: string, pageOrigin: string): boolean {
  try {
    const u = new URL(rawUrl, pageOrigin);
    const page = new URL(pageOrigin);
    return u.host === page.host && u.protocol.replace('ws', 'http') === page.protocol;
  } catch {
    return false;
  }
}

function extractUrl(input: unknown, init?: RequestInit): { url: string; method: string; body: string } {
  let url = '';
  let method = 'GET';
  let body = '';
  if (typeof input === 'string') {
    url = input;
    method = init?.method ?? 'GET';
    body = bodyToString(init?.body);
  } else if (input instanceof Request) {
    url = input.url;
    method = init?.method ?? input.method;
    // Request  body 只能异步读；优先取 init.body，否则标记待异步判定
    body = init?.body ? bodyToString(init.body) : '[request-stream]';
  }
  return { url, method: method.toUpperCase(), body };
}

function bodyToString(body: BodyInit | null | undefined): string {
  if (body == null) return '';
  if (typeof body === 'string') return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof FormData) {
    const parts: string[] = [];
    body.forEach((v, k) => parts.push(`${k}=${typeof v === 'string' ? v : '[file]'}`));
    return parts.join('&');
  }
  if (body instanceof Blob) return '[blob]';
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return '[binary]';
  return String(body);
}

export function installNetworkHooks(api: GuardApi): void {
  const refs = api.refs;
  const { fetch: nativeFetch, XMLHttpRequest: NativeXHR, sendBeacon: nativeBeacon } = refs;

  // ---------------- fetch ----------------
  const hookedFetch = function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    // 内部上报直接放行
    if ((init as Record<string, unknown> | undefined)?.[INTERNAL_KEY] === true ||
        (input instanceof Request && (input as unknown as Record<string, unknown>)[INTERNAL_KEY])) {
      return nativeFetch(input as RequestInfo, init);
    }
    const frame = parseStackFrame(refs.Error);
    const req = extractUrl(input, init);
    const decision = api.inspectOutbound(
      { url: req.url, channel: 'fetch', method: req.method, body: req.body },
      frame,
    );
    if (decision.verdict === 'block') {
      return fakeBlockedResponse(req.url);
    }
    // Request 流请求：异步补一次判定，命中则丢弃响应体（请求已无法撤回时的兜底）
    const p = nativeFetch(input as RequestInfo, init);
    if (req.body === '[request-stream]' && typeof input !== 'string') {
      (input as Request)
        .clone()
        .text()
        .then((text) => {
          const d2 = api.inspectOutbound(
            { url: req.url, channel: 'fetch', method: req.method, body: text },
            frame,
          );
          if (d2.verdict === 'block') {
            // 事件已在 inspectOutbound 内产出；请求无法撤回时关闭连接避免响应体被脚本消费
            p.then((r) => r.body?.cancel()).catch(() => undefined);
          }
        })
        .catch(() => undefined);
    }
    return p;
  } as typeof fetch;
  disguiseNative(hookedFetch as unknown as AnyFn, nativeFetch as unknown as AnyFn);
  lockProperty(refs, window, 'fetch', hookedFetch);

  // ---------------- XMLHttpRequest ----------------
  class HookedXHR extends NativeXHR {
    private pgUrl = '';
    private pgMethod = 'GET';
    private pgFrame = '';

    open(method: string, url: string | URL, ...rest: unknown[]): void {
      this.pgMethod = method;
      this.pgUrl = String(url);
      this.pgFrame = parseStackFrame(refs.Error);
      return super.open(method, url, ...(rest as [boolean]));
    }

    send(body?: Document | XMLHttpRequestBodyInit | null): void {
      const decision = api.inspectOutbound(
        {
          url: this.pgUrl,
          channel: 'xhr',
          method: this.pgMethod,
          body: bodyToString((body ?? null) as BodyInit | null),
        },
        this.pgFrame,
      );
      if (decision.verdict === 'block') {
        this.simulateBlocked();
        return;
      }
      return super.send(body);
    }

    private simulateBlocked(): void {
      const self = this;
      // 让恶意脚本看到一次"成功但空"的响应，避免抛异常暴露防护
      refs.setTimeout(() => {
        Object.defineProperty(self, 'readyState', { value: 4, configurable: true });
        Object.defineProperty(self, 'status', { value: 204, configurable: true });
        Object.defineProperty(self, 'statusText', { value: 'No Content', configurable: true });
        Object.defineProperty(self, 'responseText', { value: '', configurable: true });
        Object.defineProperty(self, 'response', { value: '', configurable: true });
        try {
          self.dispatchEvent(new Event('readystatechange'));
          self.dispatchEvent(new ProgressEvent('load', { total: 0, loaded: 0 }));
          self.dispatchEvent(new ProgressEvent('loadend', { total: 0, loaded: 0 }));
        } catch {
          /* ignore */
        }
      }, 0);
    }
  }
  disguiseNative(HookedXHR as unknown as AnyFn, NativeXHR as unknown as AnyFn);
  lockProperty(refs, window, 'XMLHttpRequest', HookedXHR);

  // ---------------- navigator.sendBeacon ----------------
  if (nativeBeacon) {
    const hookedBeacon = function (url: string | URL, data?: BodyInit | null): boolean {
      const frame = parseStackFrame(refs.Error);
      const decision = api.inspectOutbound(
        { url: String(url), channel: 'beacon', method: 'POST', body: bodyToString(data ?? null) },
        frame,
      );
      if (decision.verdict === 'block') return true; // 谎称已入队
      return nativeBeacon(url, data);
    } as Navigator['sendBeacon'];
    disguiseNative(hookedBeacon as unknown as AnyFn, nativeBeacon as unknown as AnyFn);
    lockProperty(refs, navigator, 'sendBeacon', hookedBeacon);
  }

  // ---------------- WebSocket ----------------
  const NativeWS = window.WebSocket;
  if (NativeWS) {
    class HookedWS extends NativeWS {
      constructor(url: string | URL, protocols?: string | string[]) {
        const frame = parseStackFrame(refs.Error);
        // 同源 WS（Vite HMR、站内推送等页面自身基础设施）直接放行，
        // 避免开发期热更新通道或站内信被第三方策略误伤
        const isSameOrigin = isSameOriginUrl(String(url), api.origin);
        const decision = isSameOrigin
          ? { verdict: 'allow' as const }
          : api.inspectOutbound(
              { url: String(url), channel: 'websocket', method: 'WS', body: '' },
              frame,
            );
        if (decision.verdict === 'block') {
          // 不能调用 super(url) —— 那会真的建立连接。连本地无效端口后立即关闭。
          super('ws://127.0.0.1:0/__payguard_blocked__');
          refs.setTimeout(() => this.close(), 0);
          return;
        }
        super(url, protocols as string | string[] | undefined);
        // 连接建立后继续检查每条消息
        this.addEventListener('open', () => {
          const nativeSend = this.send.bind(this);
          try {
            refs.defineProperty(this, 'send', {
              value: (data: string | ArrayBufferLike | Blob | ArrayBufferView) => {
                const d = api.inspectOutbound(
                  { url: String(url), channel: 'websocket', method: 'WS-MSG', body: typeof data === 'string' ? data : '[binary]' },
                  frame,
                );
                if (d.verdict !== 'block') nativeSend(data);
              },
              writable: false,
              configurable: false,
            });
          } catch {
            /* 个别浏览器锁定实例方法：构造器级 URL 拦截仍生效 */
          }
        });
      }
    }
    disguiseNative(HookedWS as unknown as AnyFn, NativeWS as unknown as AnyFn);
    lockProperty(refs, window, 'WebSocket', HookedWS);
  }

  // ---------------- EventSource ----------------
  const NativeES = window.EventSource;
  if (NativeES) {
    class HookedES extends NativeES {
      constructor(url: string | URL, config?: EventSourceInit) {
        const frame = parseStackFrame(refs.Error);
        const isSameOrigin = isSameOriginUrl(String(url), api.origin);
        const decision = isSameOrigin
          ? { verdict: 'allow' as const }
          : api.inspectOutbound(
              { url: String(url), channel: 'eventsource', method: 'GET', body: '' },
              frame,
            );
        if (decision.verdict === 'block') {
          super('about:blank');
          refs.setTimeout(() => this.close(), 0);
          return;
        }
        super(url, config);
      }
    }
    disguiseNative(HookedES as unknown as AnyFn, NativeES as unknown as AnyFn);
    lockProperty(refs, window, 'EventSource', HookedES);
  }
}

function fakeBlockedResponse(url: string): Promise<Response> {
  // 204 响应按规范不能带 body；用 null 构造，避免 Response 构造抛错
  const p = Promise.resolve(new Response(null, {
    status: 204,
    statusText: 'No Content',
    headers: { 'x-payguard': 'blocked' },
  }));
  return p.then((r) => {
    try {
      Object.defineProperty(r, 'url', { value: url, configurable: true });
    } catch {
      /* ignore */
    }
    return r;
  });
}

export type { OutboundInput };
