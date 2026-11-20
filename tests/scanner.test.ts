import { describe, expect, it } from 'vitest';
import { SecretScanner } from '../src/guard/core/scanner';

const PAN = '4242424242424242';

function scannerWithCard() {
  const s = new SecretScanner();
  s.register({ exact: '4242 4242 4242 4242', compact: PAN, last4: '4242', dataClass: 'payment', fieldLabel: '银行卡号' });
  s.register({ exact: 'zhangsan@example.com', compact: 'zhangsan@example.com', dataClass: 'contact', fieldLabel: '邮箱' });
  s.register({ exact: '123', compact: '123', dataClass: 'payment', fieldLabel: 'CVV' });
  return s;
}

describe('SecretScanner 载荷扫描', () => {
  it('明文命中卡号', () => {
    const hits = scannerWithCard().scan(`payload={"card":"${PAN}"}`);
    expect(hits.some((h) => h.fingerprint.fieldLabel === '银行卡号')).toBe(true);
  });

  it('带分隔符的卡号经数字重组命中', () => {
    const hits = scannerWithCard().scan('cc=4242-4242 4242-4242&x=1');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].via).toContain('digit-reassembly');
  });

  it('base64 编码外发照样命中', () => {
    const encoded = btoa(JSON.stringify({ card: PAN }));
    const hits = scannerWithCard().scan(`log=${encoded}`);
    expect(hits.some((h) => h.via.includes('base64'))).toBe(true);
  });

  it('URL 编码外发命中', () => {
    const hits = scannerWithCard().scan(`cc=${encodeURIComponent('4242 4242 4242 4242')}`);
    expect(hits.some((h) => h.fingerprint.dataClass === 'payment')).toBe(true);
  });

  it('单参数内分隔符变形（空格/连字符）经数字重组命中；更短的分片由污点层兜底', () => {
    const hits = scannerWithCard().scan(`data=${PAN.slice(0, 8)}%20${PAN.slice(8)}`);
    expect(hits.some((h) => h.fingerprint.dataClass === 'payment')).toBe(true);
  });

  it('未登记但 Luhn 合法的 PAN 兜底命中', () => {
    const hits = new SecretScanner().scan('card=5555555555554444');
    expect(hits.some((h) => h.via.includes('luhn-unregistered'))).toBe(true);
  });

  it('普通文本零误报', () => {
    const hits = scannerWithCard().scan('order=ORD-2026-1121&amount=69900&phone=13800138000');
    expect(hits.filter((h) => h.fingerprint.dataClass === 'payment')).toHaveLength(0);
  });

  it('孤立 CVV 不告警，与卡号同现才采信', () => {
    const s = scannerWithCard();
    // 无 cvc/cvv 关键字、无卡号的普通短数字载荷不应产生支付命中
    expect(s.scan('order_seq=123&qty=2')).toHaveLength(0);
    const hits = s.scan(JSON.stringify({ pan: PAN, cvv: '123' }));
    expect(hits.some((h) => h.fingerprint.fieldLabel === 'CVV')).toBe(true);
  });

  it('邮箱明文命中', () => {
    const hits = scannerWithCard().scan('user=zhangsan@example.com');
    expect(hits.some((h) => h.fingerprint.fieldLabel === '邮箱')).toBe(true);
  });
});
