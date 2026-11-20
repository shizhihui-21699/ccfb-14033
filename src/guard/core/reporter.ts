/**
 * Reporter —— 安全事件上报
 *  - 页面内事件总线（演示面板实时订阅）
 *  - 服务端上报：优先 sendBeacon，失败回退 fetch（均使用启动时保存的原生引用）
 *  - 离线/失败队列：localStorage 持久化，下次启动补报
 *  - 页面隐藏时 flush
 */
import type { EventListener, GuardConfig, SecurityEvent } from '../types';
import type { NativeRefs } from './utils';
import { genId } from './utils';

const QUEUE_KEY = '__payguard_pending_events__';

export class Reporter {
  private listeners = new Set<EventListener>();
  private queue: SecurityEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private config: GuardConfig,
    private refs: NativeRefs,
  ) {
    try {
      const raw = window.localStorage.getItem(QUEUE_KEY);
      if (raw) this.queue = JSON.parse(raw) as SecurityEvent[];
    } catch {
      this.queue = [];
    }
    // 页面卸载前尽力补报
    window.addEventListener('pagehide', () => this.flush(true), true);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') this.flush(true);
    });
  }

  subscribe(fn: EventListener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(partial: Omit<SecurityEvent, 'id' | 'ts'>): SecurityEvent {
    const event: SecurityEvent = { id: genId(), ts: Date.now(), ...partial };
    // 1) 页面内实时通知
    this.listeners.forEach((fn) => {
      try {
        fn(event);
      } catch {
        /* 监听器异常不影响防护 */
      }
    });
    if (this.config.debug) {
      // eslint-disable-next-line no-console
      console[event.kind === 'block' || event.kind === 'tamper' ? 'warn' : 'log'](
        `[PayGuard] ${event.kind}: ${event.detail}`,
        event,
      );
    }
    // 2) 服务端上报（批量、节流）
    this.queue.push(event);
    this.persist();
    if (!this.flushTimer) {
      this.flushTimer = this.refs.setTimeout(() => this.flush(false), 1500);
    }
    return event;
  }

  private persist(): void {
    try {
      // 只保留最近 50 条，避免撑爆 localStorage
      window.localStorage.setItem(QUEUE_KEY, JSON.stringify(this.queue.slice(-50)));
    } catch {
      /* 隐私模式等场景忽略 */
    }
  }

  flush(useBeacon: boolean): void {
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
        /* fall through to fetch */
      }
    }
    this.refs
      .fetch(this.config.reportEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: json,
        keepalive: true,
        // 内部标记：网络层据此跳过对自身上报的检查
        payguardInternal: true,
      } as RequestInit & { payguardInternal?: boolean })
      .then(() => {
        if (this.flushTimer) {
          clearTimeout(this.flushTimer);
          this.flushTimer = null;
        }
      })
      .catch(() => {
        // 上报失败放回队列，下次补报
        this.queue.unshift(...batch);
        this.persist();
      });
  }
}
