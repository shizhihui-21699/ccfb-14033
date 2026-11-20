/**
 * 演示环境默认策略配置 —— 真实部署时按实际供应商清单维护
 */
import type { GuardConfig } from './types';

export const defaultConfig: GuardConfig = {
  reportEndpoint: '/payguard/events',
  blockOnTaint: true,
  heartbeatMs: 5000,
  debug: true,
  sensitiveFields: [
    { match: ['card', 'cc-number', '卡号', 'bank-card', 'pan'], dataClass: 'payment', label: '银行卡号' },
    { match: ['cvv', 'cvc', 'security-code', '安全码'], dataClass: 'payment', label: 'CVV' },
    { match: ['exp', 'valid', '有效期'], dataClass: 'payment', label: '有效期' },
    { match: ['name', '姓名', 'cardholder'], dataClass: 'contact', label: '持卡人姓名' },
    { match: ['email', '邮箱', 'mail'], dataClass: 'contact', label: '邮箱' },
    { match: ['phone', '手机', 'tel'], dataClass: 'contact', label: '手机号' },
    { match: ['address', '地址'], dataClass: 'contact', label: '账单地址' },
  ],
  services: [
    {
      id: 'self',
      origins: [window.location.origin],
      trust: 'trusted',
      dataAllowlist: ['payment', 'contact', 'usage'],
      label: '本站（同源结算接口）',
      pathAllowlist: ['/api/checkout', '/payguard/'],
    },
    {
      id: 'analytics',
      origins: ['/vendor/analytics', 'metrics.example.com'],
      trust: 'observed',
      dataAllowlist: ['usage'],
      channels: ['fetch', 'xhr', 'beacon', 'image'],
      label: '流量统计',
    },
    {
      id: 'chat',
      origins: ['/vendor/chat', 'chat.example.com'],
      trust: 'observed',
      dataAllowlist: ['contact', 'usage'],
      channels: ['fetch', 'xhr', 'websocket'],
      label: '在线客服',
    },
    {
      id: 'ads',
      origins: ['/vendor/ads', 'ads.example.com'],
      trust: 'observed',
      dataAllowlist: ['usage'],
      channels: ['image', 'fetch', 'xhr'],
      label: '广告转化',
    },
    {
      id: 'abtest',
      origins: ['/vendor/abtest', 'featureflags.example.com'],
      trust: 'observed',
      dataAllowlist: ['usage'],
      channels: ['fetch', 'xhr'],
      label: 'A/B 实验平台',
    },
    // 被篡改样本使用的外发目的地：配置里不存在 = 未知目标，命中即阻断
    {
      id: 'evil-collector',
      origins: ['evil-collector.example', 'exfil.example', 'stats-cdn.example', '127.0.0.1:0'],
      trust: 'blocked',
      dataAllowlist: [],
      label: '已知恶意外收（演示）',
    },
  ],
  protectedScripts: [], // 由 index.html 启动时注入 integrity.generated 的内容
};
