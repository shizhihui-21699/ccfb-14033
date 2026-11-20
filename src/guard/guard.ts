/**
 * Guard —— PayGuard 主类，组合所有检测/拦截/上报模块
 */
import type {
  GuardApi,
  OutboundInput,
} from './context';
import type {
  GuardConfig,
  PolicyDecision,
  SecurityEvent,
  ServiceConfig,
} from './types';
import { captureNatives, frameUrl, parseStackFrame, payloadPreview } from './core/utils';
import { Reporter } from './core/reporter';
import { SecretScanner } from './core/scanner';
import { TaintRegistry } from './core/taint';
import { ServiceRegistry } from './core/services';
import { PolicyEngine } from './core/policy';
import { FieldWatcher } from './core/field-watcher';
import { installNetworkHooks } from './hooks/network-hooks';
import { installDomHooks, runSilent } from './hooks/dom-hooks';
import { installResourceHooks } from './hooks/resource-hooks';
import { installNavHooks } from './hooks/nav-hooks';
import { installScriptHooks, type ScriptGate } from './hooks/script-hooks';
import { installTamperHooks, type SnapshotEntry } from './hooks/tamper-hooks';

export class Guard implements GuardApi, ScriptGate {
  config: GuardConfig;
  refs = captureNatives();
  reporter: Reporter;
  origin: string;

  private scanner = new SecretScanner();
  private taint = new TaintRegistry();
  private services: ServiceRegistry;
  private policy: PolicyEngine;
  private fields: FieldWatcher;
  private stopHeartbeat: (() => void) | null = null;
  private ownListenerSet = new WeakSet<EventListenerOrEventListenerObject>();

  constructor(config: GuardConfig) {
    this.config = config;
    this.origin = window.location.origin;
    this.reporter = new Reporter(config, this.refs);
    this.services = new ServiceRegistry(config.services);
    this.policy = new PolicyEngine(this.services, this.taint, this.origin, config.blockOnTaint);
    this.fields = new FieldWatcher(config, this.scanner);
  }

  // ---------- GuardApi ----------

  identifyInitiator(stackFrame: string): string {
    const url = frameUrl(stackFrame);
    const svc = this.services.resolve(url, this.origin);
    return svc?.id ?? 'unknown';
  }

  inspectOutbound(input: OutboundInput, stackFrame: string): PolicyDecision {
    const initiatorService = this.identifyInitiator(stackFrame);
    const combined = `${input.url}\n${input.body}`;
    const hits = this.scanner.scan(combined);
    const decision = this.policy.evaluate(
      {
        url: input.url,
        channel: input.channel,
        method: input.method,
        body: input.body,
        stackFrame,
        initiatorService,
      },
      hits,
    );

    if (decision.verdict === 'block') {
      this.reporter.emit({
        kind: 'block',
        channel: input.channel,
        reason: decision.reason,
        serviceId: initiatorService,
        targetUrl: input.url,
        dataClass: hits[0]?.fingerprint.dataClass,
        fieldLabel: hits[0]?.fingerprint.fieldLabel,
        detail: decision.detail,
        stackFrame,
        payloadPreview: input.body ? payloadPreview(input.body) : undefined,
      });
    } else if (decision.verdict === 'report') {
      this.reporter.emit({
        kind: 'alert',
        channel: input.channel,
        reason: decision.reason,
        serviceId: initiatorService,
        targetUrl: input.url,
        detail: decision.detail,
        stackFrame,
      });
    }
    return decision;
  }

  noteSensitiveRead(el: Element, stackFrame: string): void {
    const def = this.fields.getFieldDef(el);
    if (!def) return;
    const serviceId = this.identifyInitiator(stackFrame);
    const rec = this.taint.noteRead(serviceId, def.label, def.dataClass, stackFrame);
    if (rec) {
      this.reporter.emit({
        kind: 'observation',
        serviceId,
        fieldLabel: def.label,
        dataClass: def.dataClass,
        detail: `服务 ${serviceId} 读取了敏感字段「${def.label}」`,
        stackFrame,
      });
    }
  }

  isWatchedField(el: Element): boolean {
    return runSilent(() => this.fields.getFieldDef(el) !== null);
  }

  markOwnListener(fn: EventListenerOrEventListenerObject): void {
    this.ownListenerSet.add(fn);
  }

  isOwnListener(fn: EventListenerOrEventListenerObject): boolean {
    return this.ownListenerSet.has(fn);
  }

  reportTamper(detail: string, stackFrame: string): SecurityEvent {
    return this.reporter.emit({
      kind: 'tamper',
      reason: 'guard-tamper',
      serviceId: this.identifyInitiator(stackFrame),
      detail,
      stackFrame,
    });
  }

  // ---------- ScriptGate ----------

  checkScriptUrl(url: string): { ok: boolean; reason?: string; detail?: string } {
    if (!/^https?:\/\//.test(url) && !url.startsWith('/')) return { ok: true }; // data:、blob: 由调用方策略另行处理
    const extra = (this.config as GuardConfig & { extraAllowedScriptPrefixes?: string[] })
      .extraAllowedScriptPrefixes ?? [];

    // SRI 篡改演示路由 /vendor/_tampered/x.js：其基线 /vendor/x.js 在完整性清单内，
    // 放行到加载环节，由 verifyIntegrity 用基线哈希判定内容是否被篡改。
    if (url.includes('/_tampered/')) {
      const normalized = url.replace('/_tampered', '');
      const protectedMatch = this.config.protectedScripts?.some((p) =>
        normalized.includes(new URL(p.src, this.origin).pathname),
      );
      if (protectedMatch) return { ok: true };
    }

    const authorized = this.services.isAuthorizedScript(url, this.origin, extra);
    if (!authorized) {
      return {
        ok: false,
        reason: 'unauthorized-script',
        detail: `脚本不在供应商允许名单内：${url}`,
      };
    }
    return { ok: true };
  }

  async verifyIntegrity(src: string, expected: string): Promise<boolean> {
    try {
      const res = await this.refs.fetch(src, { cache: 'no-store' } as RequestInit);
      const buf = await res.arrayBuffer();
      const hash = await crypto.subtle.digest('SHA-384', buf);
      const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
      return expected === `sha384-${base64}`;
    } catch {
      return true; // 网络异常不误伤，交由其他通道监控
    }
  }

  // ---------- 安装 ----------

  install(): void {
    // 注意顺序：DOM 读取钩子先装，确保后续任何脚本读值都被记录。
    // 各层独立容错：单个通道钩子在个别浏览器上失败，不拖垮整套防护。
    const steps: Array<[string, () => void]> = [
      ['dom', () => installDomHooks(this)],
      ['network', () => installNetworkHooks(this)],
      ['resource', () => installResourceHooks(this)],
      ['nav', () => installNavHooks(this)],
      ['script', () => installScriptHooks(this, this)],
      [
        'tamper',
        () => {
          // 传入快照提供者而非快照本身：基线在首次心跳（全部钩子就位后）才采集
          this.stopHeartbeat = installTamperHooks(this, () => this.collectSnapshots());
        },
      ],
    ];
    for (const [name, step] of steps) {
      try {
        step();
      } catch (err) {
        this.reporter.emit({
          kind: 'tamper',
          reason: 'guard-tamper',
          serviceId: 'self',
          detail: `防护层 ${name} 安装异常（已降级，其余通道仍生效）：${(err as Error).message}`,
          stackFrame: 'install',
        });
      }
    }

    // 标记我们自己的 capture 监听器（FieldWatcher 内部已注册 input/change）
    this.reporter.emit({
      kind: 'observation',
      serviceId: 'self',
      detail: `PayGuard 已启动，监控 ${this.config.services.length} 个服务配置、${this.collectSnapshots().length} 个受保护 API`,
      stackFrame: 'boot',
    });
  }

  private collectSnapshots(): SnapshotEntry[] {
    const get = (obj: object, key: string) => ({
      label: key,
      obj,
      key,
      expected: (obj as Record<string, unknown>)[key],
    });
    const snaps: SnapshotEntry[] = [
      get(window, 'fetch'),
      get(window, 'XMLHttpRequest'),
      get(window, 'WebSocket'),
      get(window, 'EventSource'),
      get(window, 'FontFace'),
      get(navigator, 'sendBeacon'),
      get(Object, 'defineProperty'),
      get(EventTarget.prototype, 'removeEventListener'),
      get(Element.prototype, 'setAttribute'),
    ];
    const vd = this.refs.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (vd?.get) {
      snaps.push({ label: 'input.value getter', obj: HTMLInputElement.prototype, key: 'value', expected: vd.get });
    }
    return snaps.filter((s) => s.expected != null);
  }

  /** 供演示面板使用的调试 API（挂在 window.__PAYGUARD__，不可枚举） */
  debugApi(): object {
    return {
      config: this.config,
      subscribe: (fn: (e: SecurityEvent) => void) => this.reporter.subscribe(fn),
      taint: () => this.taint.snapshot(),
      services: (): ServiceConfig[] => this.services.all(),
      fingerprints: () => this.scanner.size(),
    };
  }
}
