/**
 * dom-hooks —— 敏感输入框"读取"监控
 *
 * 钩住 value getter / getAttribute：任何脚本（含 jQuery .val()，
 * 其内部仍走 value getter）读取受监控字段时，登记污点。
 * PayGuard 自身读取通过 runSilent 豁免，避免自污染。
 */
import type { GuardApi } from '../context';
import type { NativeRefs } from '../core/utils';
import { parseStackFrame } from '../core/utils';

let silent = false;

/** PayGuard 内部代码读取 DOM 时包一层，避免产生自身污点 */
export function runSilent<T>(fn: () => T): T {
  const prev = silent;
  silent = true;
  try {
    return fn();
  } finally {
    silent = prev;
  }
}

export function installDomHooks(api: GuardApi): void {
  const refs = api.refs;
  const d = refs.getOwnPropertyDescriptor;

  const wrapValueGetter = (proto: object, name = 'value') => {
    const desc = d(proto, name);
    if (!desc?.get) return;
    const nativeGet = desc.get;
    const nativeSet = desc.set;
    refs.defineProperty(proto, name, {
      get() {
        const val = nativeGet.call(this) as unknown;
        if (!silent && this instanceof Element && api.isWatchedField(this)) {
          api.noteSensitiveRead(this, parseStackFrame(refs.Error));
        }
        return val;
      },
      set(v: unknown) {
        nativeSet?.call(this, v);
      },
      configurable: false,
      enumerable: desc.enumerable,
    });
  };

  wrapValueGetter(HTMLInputElement.prototype);
  wrapValueGetter(HTMLTextAreaElement.prototype);
  wrapValueGetter(HTMLSelectElement.prototype);

  // getAttribute('value') / getAttributeNode 等旁路读取
  const attrDesc = d(Element.prototype, 'getAttribute');
  const nativeGetAttr = attrDesc?.value as ((name: string) => string | null) | undefined;
  if (nativeGetAttr) {
    refs.defineProperty(Element.prototype, 'getAttribute', {
      value: function (name: string): string | null {
        const ret = nativeGetAttr.call(this, name) as string | null;
        if (
          !silent &&
          this instanceof Element &&
          api.isWatchedField(this) &&
          name.toLowerCase() === 'value' &&
          ret != null
        ) {
          api.noteSensitiveRead(this, parseStackFrame(refs.Error));
        }
        return ret;
      },
      writable: false,
      configurable: false,
    });
  }
}
