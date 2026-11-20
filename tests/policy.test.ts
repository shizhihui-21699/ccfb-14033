import { describe, expect, it } from 'vitest';
import { PolicyEngine } from '../src/guard/core/policy';
import { ServiceRegistry } from '../src/guard/core/services';
import { TaintRegistry } from '../src/guard/core/taint';
import { SecretScanner } from '../src/guard/core/scanner';
import type { GuardConfig, NetworkRequest, ScanHit } from '../src/guard/types';

const ORIGIN = 'https://shop.example';

const config: GuardConfig = {
  reportEndpoint: '',
  blockOnTaint: true,
  heartbeatMs: 5000,
  debug: false,
  sensitiveFields: [],
  services: [
    { id: 'self', origins: [ORIGIN], trust: 'trusted', dataAllowlist: ['payment', 'contact', 'usage'], pathAllowlist: ['/api/checkout'], label: '本站' },
    { id: 'analytics', origins: ['/vendor/analytics'], trust: 'observed', dataAllowlist: ['usage'], channels: ['fetch', 'beacon', 'image'], label: '统计' },
    { id: 'chat', origins: ['/vendor/chat'], trust: 'observed', dataAllowlist: ['contact', 'usage'], channels: ['fetch', 'websocket'], label: '客服' },
    { id: 'evil', origins: ['evil.example'], trust: 'blocked', dataAllowlist: [], label: '恶意外收' },
  ],
};

function build() {
  const services = new ServiceRegistry(config.services);
  const taint = new TaintRegistry();
  const policy = new PolicyEngine(services, taint, ORIGIN, true);
  return { services, taint, policy };
}

const paymentHit: ScanHit[] = [{
  fingerprint: { exact: '4242424242424242', compact: '4242424242424242', last4: '4242', dataClass: 'payment', fieldLabel: '银行卡号' },
  matched: '4242424242424242',
  via: 'plain',
}];

function req(over: Partial<NetworkRequest>): NetworkRequest {
  return { url: '/vendor/analytics/collect', channel: 'fetch', method: 'POST', body: '', stackFrame: '', initiatorService: 'analytics', ...over };
}

describe('PolicyEngine 策略判定', () => {
  it('同源结算接口带支付数据 → 放行', () => {
    const { policy } = build();
    const d = policy.evaluate(
      req({ url: `${ORIGIN}/api/checkout`, initiatorService: 'self', body: 'card=4242' }),
      paymentHit,
    );
    expect(d.verdict).toBe('allow');
  });

  it('统计脚本把卡号发到自己域名 → 阻断（无 payment 授权）', () => {
    const { policy } = build();
    const d = policy.evaluate(req({ url: '/vendor/analytics/collect', body: 'card=4242' }), paymentHit);
    expect(d.verdict).toBe('block');
    expect(d.reason).toBe('sensitive-fingerprint');
  });

  it('未知外发域名 + 卡号 → 阻断', () => {
    const { policy } = build();
    const d = policy.evaluate(req({ url: 'https://unknown.example/x', body: 'pan' }), paymentHit);
    expect(d.verdict).toBe('block');
  });

  it('无指纹但读过敏感字段，发往未授权目标 → 污点阻断（加密载荷也拦）', () => {
    const { policy, taint } = build();
    taint.noteRead('analytics', '银行卡号', 'payment', 'frame');
    const d = policy.evaluate(req({ url: '/vendor/analytics/collect', body: 'ENCRYPTED-BLOB' }), []);
    expect(d.verdict).toBe('block');
    expect(d.reason).toBe('taint-not-allowed');
  });

  it('客服读联系信息后发联系数据 → 放行（contact 在授权内）', () => {
    const { policy, taint } = build();
    taint.noteRead('chat', '邮箱', 'contact', 'frame');
    const contactHit: ScanHit[] = [{
      fingerprint: { exact: 'a@b.com', compact: 'a@b.com', dataClass: 'contact', fieldLabel: '邮箱' },
      matched: 'a@b.com',
      via: 'plain',
    }];
    const d = policy.evaluate(
      req({ url: '/vendor/chat/sync', initiatorService: 'chat', channel: 'fetch' }),
      contactHit,
    );
    expect(d.verdict).toBe('allow');
  });

  it('通道不在允许名单 → 阻断（统计不允许 websocket）', () => {
    const { policy, taint } = build();
    taint.noteRead('analytics', '邮箱', 'contact', 'frame');
    const d = policy.evaluate(
      req({ url: '/vendor/analytics/ws', channel: 'websocket', body: '' }),
      [],
    );
    expect(d.verdict).toBe('block');
  });

  it('封禁服务任何外联 → 阻断', () => {
    const { policy } = build();
    const d = policy.evaluate(req({ url: 'https://evil.example/ping', initiatorService: 'evil' }), []);
    expect(d.verdict).toBe('block');
    expect(d.reason).toBe('blocked-destination');
  });

  it('普通 usage 上报无污点无指纹 → 放行', () => {
    const { policy } = build();
    const d = policy.evaluate(req({ url: '/vendor/analytics/collect', body: 'event=click' }), []);
    expect(d.verdict).toBe('allow');
  });
});
