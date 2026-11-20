/**
 * nav-hooks —— 页面导航外发通道
 * window.open / location 赋值 / location.assign / location.replace
 */
import type { GuardApi } from '../context';
import type { NativeRefs } from '../core/utils';
import { disguiseNative, lockProperty, parseStackFrame } from '../core/utils';

export function installNavHooks(api: GuardApi): void {
  const refs = api.refs;

  const check = (url: string) =>
    api.inspectOutbound(
      { url, channel: 'navigation', method: 'GET', body: '' },
      parseStackFrame(refs.Error),
    );

  // window.open
  const nativeOpen = window.open;
  const hookedOpen = function (url?: string | URL, ...rest: unknown[]): Window | null {
    if (url) {
      const decision = check(String(url));
      if (decision.verdict === 'block') return null;
    }
    return nativeOpen.call(window, url, ...(rest as never[]));
  } as typeof window.open;
  disguiseNative(hookedOpen as (...a: unknown[]) => unknown, nativeOpen as (...a: unknown[]) => unknown);
  lockProperty(refs, window, 'open', hookedOpen);

  // location.assign / replace
  // 部分浏览器（Chromium）把它们实现为 location 实例上不可配置的自身属性，
  // 无法重定义——此时原生方法本身不可变，直接跳过实例包装，仅尝试原型层。
  const nativeAssign = location.assign.bind(location);
  const nativeReplace = location.replace.bind(location);
  const canWrap = (obj: object, name: string): boolean => {
    const d = Object.getOwnPropertyDescriptor(obj, name);
    return !d || d.configurable === true;
  };

  const wrapLoc = (name: 'assign' | 'replace', native: (u: string) => void) => {
    const wrapper = (url: string | URL) => {
      const decision = check(String(url));
      if (decision.verdict === 'block') return;
      native(String(url));
    };
    if (canWrap(location, name)) {
      try {
        refs.defineProperty(location, name, {
          value: wrapper,
          writable: false,
          configurable: false,
        });
        return;
      } catch {
        /* 落到原型层 */
      }
    }
    if (canWrap(Location.prototype, name)) {
      try {
        refs.defineProperty(Location.prototype, name, {
          value: wrapper,
          writable: false,
          configurable: false,
        });
      } catch {
        /* 浏览器完全锁定，原生方法不可变，无需包装 */
      }
    }
  };
  wrapLoc('assign', nativeAssign);
  wrapLoc('replace', nativeReplace);

  // location.href setter
  const locDesc = refs.getOwnPropertyDescriptor(Location.prototype, 'href');
  if (locDesc?.set) {
    const nativeSet = locDesc.set;
    refs.defineProperty(Location.prototype, 'href', {
      get() {
        return locDesc.get?.call(this);
      },
      set(v: string) {
        const decision = check(String(v));
        if (decision.verdict === 'block') return;
        nativeSet.call(this, v);
      },
      configurable: false,
      enumerable: locDesc.enumerable,
    });
  }
}
