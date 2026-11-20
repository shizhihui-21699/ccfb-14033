import { describe, expect, it } from 'vitest';
import { luhnCheck, compactDigits, maskSecret } from '../src/guard/core/luhn';

describe('Luhn 校验', () => {
  it('接受合法测试卡号', () => {
    expect(luhnCheck('4242424242424242')).toBe(true);
    expect(luhnCheck('5555555555554444')).toBe(true);
    expect(luhnCheck('378282246310005')).toBe(true); // Amex 15 位
  });

  it('拒绝非法数字串（订单号/手机号不会误判）', () => {
    expect(luhnCheck('13800138000')).toBe(false);
    expect(luhnCheck('202611210001')).toBe(false);
    expect(luhnCheck('1234567890123')).toBe(false);
  });

  it('拒绝长度越界', () => {
    expect(luhnCheck('4242')).toBe(false);
    expect(luhnCheck('4'.repeat(20))).toBe(false);
  });

  it('compactDigits 去掉分隔符', () => {
    expect(compactDigits('4242 4242-4242 4242')).toBe('4242424242424242');
  });

  it('maskSecret 只留末四位', () => {
    expect(maskSecret('4242 4242 4242 4242')).toBe('****-****-****-4242');
  });
});
