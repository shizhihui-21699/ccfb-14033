/**
 * FieldWatcher —— 识别结算页里的敏感输入框，
 * 用户输入时把值的指纹注册进 SecretScanner。
 */
import type { GuardConfig, SecretFingerprint, SensitiveFieldDef } from '../types';
import { compactDigits, luhnCheck } from './luhn';
import type { SecretScanner } from './scanner';

const SENSITIVE_SELECTOR = 'input, textarea, select';

export class FieldWatcher {
  /** element -> 命中的字段定义 */
  private fieldMap = new WeakMap<Element, SensitiveFieldDef>();
  private known = new Set<Element>();

  constructor(
    private config: GuardConfig,
    private scanner: SecretScanner,
  ) {
    this.scanAll();
    // 动态渲染的表单也能覆盖到
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

  classify(el: Element): SensitiveFieldDef | null {
    if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement)) {
      return null;
    }
    const haystack = [
      el.getAttribute('name') ?? '',
      el.id,
      el.getAttribute('autocomplete') ?? '',
      el.getAttribute('data-pg') ?? '',
      el.getAttribute('aria-label') ?? '',
      el.getAttribute('placeholder') ?? '',
    ]
      .join(' ')
      .toLowerCase();
    // 边界匹配：token 必须以独立词出现（分隔符为非字母数字），
    // 避免 name 误命中 card-number、mail 误命中 email 之外的更长词等子串问题。
    // 中文 token 直接做包含匹配（中文没有词边界概念）。
    const hit = this.config.sensitiveFields.find((def) =>
      def.match.some((token) => {
        const t = token.toLowerCase();
        if (/[一-鿿]/.test(t)) return haystack.includes(t);
        return new RegExp(`(^|[^a-z0-9])${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`).test(haystack);
      }),
    );
    return hit ?? null;
  }

  private scanAll(): void {
    document.querySelectorAll(SENSITIVE_SELECTOR).forEach((el) => this.inspect(el));
  }

  private inspect(el: Element): void {
    if (this.known.has(el)) return;
    const def = this.classify(el);
    if (!def) return;
    this.known.add(el);
    this.fieldMap.set(el, def);
    el.setAttribute('data-pg-watched', def.dataClass);
    // 输入即注册指纹（capture 阶段，先于第三方监听器）
    el.addEventListener(
      'input',
      () => this.registerValue(el as HTMLInputElement, def),
      true,
    );
    el.addEventListener(
      'change',
      () => this.registerValue(el as HTMLInputElement, def),
      true,
    );
    // 已有的预填值
    const v = (el as HTMLInputElement).value;
    if (v) this.registerValue(el as HTMLInputElement, def);
  }

  getFieldDef(el: Element): SensitiveFieldDef | null {
    return this.fieldMap.get(el) ?? this.classify(el);
  }

  private registerValue(el: HTMLInputElement, def: SensitiveFieldDef): void {
    const raw = el.value?.trim();
    if (!raw) return;
    const fp: SecretFingerprint = {
      exact: raw,
      compact: compactDigits(raw),
      dataClass: def.dataClass,
      fieldLabel: def.label,
    };
    if (def.dataClass === 'payment' && def.label.includes('卡号')) {
      const digits = compactDigits(raw);
      if (!luhnCheck(digits)) return; // 非合法卡号不注册，降低误报
      fp.last4 = digits.slice(-4);
    }
    if (def.label === 'CVV' && !/^\d{3,4}$/.test(raw)) return;
    if (def.dataClass === 'contact' && raw.length < 3) return;
    this.scanner.register(fp);
  }
}
