/**
 * SecretScanner —— 敏感数据指纹库 + 载荷扫描器
 *
 * 应对的外发隐藏手段：
 *  - 明文 / URL 编码 / base64 编码（含一层嵌套解码）
 *  - 卡号加空格、连字符变形
 *  - 拆成多个 query 参数 / JSON 字段分片外发（数字顺序重组）
 *  - 载荷里出现未登记但 Luhn 合法的银行卡号（兜底）
 */
import type { ScanHit, SecretFingerprint } from '../types';
import { compactDigits, luhnCheck } from './luhn';

interface Candidate {
  text: string;
  via: string;
}

export class SecretScanner {
  private fingerprints: SecretFingerprint[] = [];

  register(fp: SecretFingerprint): void {
    // 去重：同字段同值只保留一份
    const exists = this.fingerprints.some(
      (f) => f.exact === fp.exact && f.fieldLabel === fp.fieldLabel,
    );
    if (!exists) this.fingerprints.push(fp);
  }

  size(): number {
    return this.fingerprints.length;
  }

  /** 生成载荷的各种解码候选 */
  private candidates(raw: string): Candidate[] {
    const out: Candidate[] = [{ text: raw, via: 'plain' }];
    try {
      const urlDecoded = decodeURIComponent(raw);
      if (urlDecoded !== raw) out.push({ text: urlDecoded, via: 'url-encoded' });
    } catch {
      /* 非法编码序列，忽略 */
    }
    // base64 片段（长度 >=16 才尝试，避免噪声）
    const b64Tokens = raw.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [];
    for (const token of b64Tokens) {
      try {
        const decoded = atob(token);
        if (!/^[\x00-\x08]/.test(decoded)) {
          out.push({ text: decoded, via: 'base64' });
          try {
            const inner = decodeURIComponent(decoded);
            if (inner !== decoded) out.push({ text: inner, via: 'base64+url' });
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* 不是合法 base64 */
      }
    }
    return out;
  }

  /**
   * 扫描任意字符串载荷，返回命中的敏感数据。
   */
  scan(raw: string): ScanHit[] {
    if (!raw || raw.length < 3) return [];
    const hits: ScanHit[] = [];
    const seen = new Set<string>();
    const pushHit = (hit: ScanHit) => {
      const key = `${hit.fingerprint.fieldLabel}:${hit.matched}:${hit.via}`;
      if (!seen.has(key)) {
        seen.add(key);
        hits.push(hit);
      }
    };

    for (const cand of this.candidates(raw)) {
      const text = cand.text;
      // 只保留"像卡号"的数字串：允许空格/连字符分隔，避免把 p1=..&p2=.. 的
      // 多个参数数字拼成一个超长假串
      const panTokens = text.match(/\d(?:\d|[- ]){11,22}\d/g) ?? [];
      const digitRuns = panTokens.map((t) => t.replace(/[ -]/g, ''));

      for (const fp of this.fingerprints) {
        // 1) 精确值直接出现（邮箱、姓名、CVV、原始卡号等）
        if (fp.exact.length >= 3 && text.includes(fp.exact)) {
          if (fp.fieldLabel === 'CVV') {
            // 三位数字误报率高：必须和卡号同时出现，或带 cvv/cvc 关键字
            const withCard = hits.some((h) => h.fingerprint.dataClass === 'payment');
            const withKeyword = /cvv|cvc|security.?code/i.test(text);
            if (!withCard && !withKeyword) continue;
          }
          pushHit({ fingerprint: fp, matched: fp.exact, via: cand.via });
          continue;
        }
        // 2) 数字顺序重组比对（对付分片、分隔符变形）：
        //    要求完整 compact 出现在某个 PAN 形态 token 内部，或直接出现在文本中
        if (fp.compact.length >= 12) {
          const inToken = digitRuns.some((run) => run.includes(fp.compact));
          const inText = text.includes(fp.compact);
          if (inToken || inText) {
            pushHit({ fingerprint: fp, matched: fp.compact, via: `${cand.via}+digit-reassembly` });
            continue;
          }
        }
        // 3) 末四位形态（同候选里存在 Luhn 合法 PAN 时采信，见下方 PAN 扫描）
      }

      // 4) 兜底：直接在载荷里找 Luhn 合法的 PAN（含空格/连字符形态）。
      //    要求长度 >=13 且命中 Luhn，避免把订单号等短数字误判。
      for (const pan of panTokens) {
        const digits = compactDigits(pan);
        if (!luhnCheck(digits)) continue;
        const registered = this.fingerprints.find(
          (f) => f.dataClass === 'payment' && (f.compact === digits || f.last4 === digits.slice(-4)),
        );
        if (registered) {
          pushHit({ fingerprint: registered, matched: digits, via: `${cand.via}+luhn` });
        } else {
          // 未登记但确实是合法卡号：合成一条支付级指纹
          pushHit({
            fingerprint: {
              exact: digits,
              compact: digits,
              last4: digits.slice(-4),
              dataClass: 'payment',
              fieldLabel: '未登记的银行卡号',
            },
            matched: digits,
            via: `${cand.via}+luhn-unregistered`,
          });
        }
      }
    }
    return hits;
  }
}
