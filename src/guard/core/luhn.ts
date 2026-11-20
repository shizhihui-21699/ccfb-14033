/**
 * Luhn 校验：13~19 位、通过 Luhn 模 10 校验的才认定为银行卡号，
 * 避免把订单号、手机号等普通数字误判成卡号。
 */
export function luhnCheck(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/** 去掉空格、连字符等常见分隔符 */
export function compactDigits(s: string): string {
  return s.replace(/[\s-]/g, '');
}

/** 卡号脱敏：只保留末四位 */
export function maskSecret(value: string): string {
  const c = compactDigits(value);
  if (c.length >= 4) return `****-****-****-${c.slice(-4)}`;
  return '****';
}
