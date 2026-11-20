/**
 * script-hooks —— 供应链入口控制
 *
 * 两道关卡：
 *  1) 加载允许名单：动态创建的 <script src> / createElement('script') 后赋值 src，
 *     URL 必须命中某个已登记服务的 origins，否则当场阻断（不发起请求、不执行）。
 *  2) SRI 完整性：配置了 integrity 清单的脚本，拉取内容计算 SHA-384，
 *     与清单不符（脚本被中途篡改）则移除节点并上报。
 *
 * 静态 <script> 标签在 guard 之前出现的情况由部署约定保证：
 * guard-bundle 必须是文档第一个脚本。
 */
import type { BlockReason } from '../types';
import type { GuardApi } from '../context';
import type { NativeRefs } from '../core/utils';
import { parseStackFrame } from '../core/utils';

export interface ScriptGate {
  checkScriptUrl(url: string): { ok: boolean; reason?: string; detail?: string };
  verifyIntegrity(src: string, expected: string): Promise<boolean>;
}

export function installScriptHooks(api: GuardApi, gate: ScriptGate): void {
  const refs = api.refs;
  const d = refs.getOwnPropertyDescriptor;

  // reason 使用结构化枚举，不再靠中文字符串猜测
  const blockScript = (
    script: HTMLScriptElement,
    reason: BlockReason,
    detail: string,
  ): void => {
    api.reporter.emit({
      kind: reason === 'integrity-mismatch' ? 'tamper' : 'block',
      channel: 'script-load',
      reason,
      serviceId: api.identifyInitiator(parseStackFrame(refs.Error)),
      targetUrl: script.src,
      detail,
      stackFrame: parseStackFrame(refs.Error),
    });
    try {
      // 摘节点前先把 src 指向空，阻断任何已排队的加载
      if (script.src !== 'about:blank') script.src = 'about:blank';
      script.remove();
    } catch {
      /* ignore */
    }
  };

  // 记录已被入口拦截的脚本节点，MutationObserver 兜底时不重复上报
  const blockedNodes = new WeakSet<HTMLScriptElement>();

  // HTMLScriptElement.src setter
  const srcDesc = d(HTMLScriptElement.prototype, 'src');
  if (srcDesc?.set) {
    const nativeSet = srcDesc.set;
    refs.defineProperty(HTMLScriptElement.prototype, 'src', {
      get() {
        return srcDesc.get?.call(this);
      },
      set(v: string) {
        const url = String(v);
        const result = gate.checkScriptUrl(url);
        if (!result.ok) {
          // 同步拦截：绝不把真实 URL 交给原生 setter，请求不会发起、代码不会执行
          blockedNodes.add(this);
          blockScript(this, 'unauthorized-script', result.detail ?? url);
          nativeSet.call(this, 'about:blank');
          return;
        }
        nativeSet.call(this, v);
        // SRI 校验（异步，不阻塞合法脚本加载；篡改命中后立即摘除）。
        // /vendor/_tampered/x.js 这类"同内容不同 URL"的投毒演示路由，
        // 归一化回基线路径 /vendor/x.js 后再查清单。
        const normalized = url.replace('/_tampered', '');
        const protectedScript = api.config.protectedScripts?.find((p) =>
          normalized.includes(new URL(p.src, location.origin).pathname),
        );
        if (protectedScript) {
          gate.verifyIntegrity(url, protectedScript.integrity).then((ok) => {
            if (!ok) {
              blockScript(this, 'integrity-mismatch', `SRI 校验失败，脚本疑似被篡改：${url}`);
            }
          });
        }
      },
      configurable: false,
      enumerable: srcDesc.enumerable,
    });
  }

  // MutationObserver 兜底：直接 innerHTML 注入、appendChild 已带 src 的节点
  new MutationObserver((mutations) => {
    for (const m of mutations) {
      m.addedNodes.forEach((node) => {
        if (!(node instanceof HTMLScriptElement) || !node.src) return;
        if (node.src === 'about:blank' || blockedNodes.has(node)) return;
        const result = gate.checkScriptUrl(node.src);
        if (!result.ok) {
          blockedNodes.add(node);
          blockScript(node, 'unauthorized-script', result.detail ?? node.src);
        }
      });
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
}
