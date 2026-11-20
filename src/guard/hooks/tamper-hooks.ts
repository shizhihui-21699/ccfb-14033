/**
 * tamper-hooks —— 抗关停 / 抗探测
 *
 * 恶意脚本常见动作：
 *  - delete window.fetch / 把 window.fetch 换成自己的实现绕过检查
 *  - Object.defineProperty(window, 'fetch', ...) 重写钩子
 *  - removeEventListener 摘掉防护的 capture 监听器
 *  - 探测钩子 toString 是否为 native、删除防护 <script> 标签
 *  - 直接改写 navigator.sendBeacon
 *
 * 对策：
 *  - 钩子本身 non-configurable，严格模式下赋值/删除直接抛 TypeError
 *  - 包装 Object.defineProperty / deleteProperty，发现针对钩子的篡改即上报
 *  - 包装 removeEventListener，防护自身监听器受保护
 *  - 心跳周期校验所有钩子描述符与函数身份，被绕过立即告警
 */
import type { GuardApi } from '../context';
import type { NativeRefs } from '../core/utils';
import { lockProperty } from '../core/utils';

export interface SnapshotEntry {
  label: string;
  obj: object;
  key: string;
  expected: unknown;
}

const HOOK_KEYS = new Set(['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon', 'FontFace']);

export function installTamperHooks(
  api: GuardApi,
  snapshotProvider: () => SnapshotEntry[],
): () => void {
  const refs = api.refs;
  const ownListeners = new WeakSet<EventListenerOrEventListenerObject>();
  api.markOwnListener = (fn) => ownListeners.add(fn);
  api.isOwnListener = (fn) => ownListeners.has(fn);

  const frame = () => {
    try {
      return new refs.Error().stack?.split('\n')[2]?.trim() ?? 'unknown';
    } catch {
      return 'unknown';
    }
  };

  // ---------------- Object.defineProperty 包装 ----------------
  const nativeDefine = Object.defineProperty;
  const hookedDefine = function <T>(obj: T, key: PropertyKey, desc: PropertyDescriptor): T {
    const keyStr = String(key);
    const isHookTarget =
      (obj === window || obj === navigator || obj === Object.prototype || obj === EventTarget.prototype) &&
      (HOOK_KEYS.has(keyStr) || keyStr === 'defineProperty' || keyStr === 'removeEventListener');
    if (isHookTarget) {
      api.reportTamper(`检测到对受保护 API ${keyStr} 的 defineProperty 重写尝试`, frame());
      // 不把 desc 应用下去：返回原对象，攻击静默失效
      return obj;
    }
    return nativeDefine(obj, key, desc);
  } as typeof Object.defineProperty;
  lockProperty(refs, Object, 'defineProperty', hookedDefine);

  // ---------------- Reflect.defineProperty 同步包装 ----------------
  const nativeReflectDefine = Reflect.defineProperty;
  refs.defineProperty(Reflect, 'defineProperty', {
    value: (target: object, key: PropertyKey, desc: PropertyDescriptor) => {
      const keyStr = String(key);
      if (target === window && HOOK_KEYS.has(keyStr)) {
        api.reportTamper(`检测到通过 Reflect.defineProperty 重写 ${keyStr} 的尝试`, frame());
        return true; // 谎称成功，实际不生效
      }
      return nativeReflectDefine(target, key, desc);
    },
    writable: false,
    configurable: false,
  });

  // ---------------- delete 操作（Reflect.deleteProperty） ----------------
  const nativeDelete = Reflect.deleteProperty;
  refs.defineProperty(Reflect, 'deleteProperty', {
    value: (target: object, key: PropertyKey) => {
      const keyStr = String(key);
      if (target === window && HOOK_KEYS.has(keyStr)) {
        api.reportTamper(`检测到删除受保护 API ${keyStr} 的尝试`, frame());
        return false;
      }
      return nativeDelete(target, key);
    },
    writable: false,
    configurable: false,
  });

  // ---------------- removeEventListener 保护 ----------------
  const nativeRemove = EventTarget.prototype.removeEventListener;
  refs.defineProperty(EventTarget.prototype, 'removeEventListener', {
    value: function (type: string, fn: EventListenerOrEventListenerObject, ...rest: unknown[]) {
      if (fn && api.isOwnListener(fn)) {
        api.reportTamper(`检测到试图移除 PayGuard 的 ${type} 监听器`, frame());
        return; // 拒绝移除
      }
      return nativeRemove.call(this, type, fn, ...(rest as [boolean | EventListenerOptions]));
    },
    writable: false,
    configurable: false,
  });

  // ---------------- 防护 <script> 标签摘除监控 ----------------
  const guardScript = document.currentScript;
  new MutationObserver((mutations) => {
    for (const m of mutations) {
      m.removedNodes.forEach((node) => {
        if (node === guardScript || (node instanceof HTMLScriptElement && /guard-bundle/.test(node.src))) {
          api.reportTamper('检测到 PayGuard 脚本标签被移除（钩子仍在内存中运行）', frame());
        }
      });
    }
  }).observe(document.documentElement, { childList: true, subtree: true });

  // ---------------- 心跳校验 ----------------
  // 基线在首次心跳时才采集：此时所有防护钩子（含本模块的 defineProperty 包装）
  // 均已安装完毕，避免把我们自己的包装误判成外部篡改。
  let snapshots: SnapshotEntry[] | null = null;
  const heartbeat = refs.setInterval(() => {
    if (!snapshots) snapshots = snapshotProvider();
    for (const snap of snapshots) {
      const desc = refs.getOwnPropertyDescriptor(snap.obj, snap.key);
      if (!desc) {
        api.reportTamper(`心跳校验：${snap.label} 描述符消失`, frame());
        continue;
      }
      const current = 'value' in desc ? desc.value : desc.get;
      if (current !== snap.expected) {
        api.reportTamper(`心跳校验：${snap.label} 已被替换为外部实现`, frame());
      }
      if (desc.writable || desc.configurable) {
        api.reportTamper(`心跳校验：${snap.label} 锁定状态被破坏`, frame());
      }
    }
  }, api.config.heartbeatMs);

  return () => clearInterval(heartbeat);
}
