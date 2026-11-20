/**
 * PayGuard 入口 —— 编译为 IIFE，必须作为页面第一个脚本同步加载。
 * 配置通过 window.__PAYGUARD_CONFIG__ 内联传入（见 index.html）。
 */
import { Guard } from './guard';
import type { GuardConfig } from './types';

declare global {
  interface Window {
    __PAYGUARD_CONFIG__: GuardConfig;
    __PAYGUARD__?: unknown;
  }
}

const config = window.__PAYGUARD_CONFIG__;
if (!config) {
  // eslint-disable-next-line no-console
  console.error('[PayGuard] 缺少 window.__PAYGUARD_CONFIG__，防护未启动');
} else {
  const guard = new Guard(config);
  guard.install();
  try {
    Object.defineProperty(window, '__PAYGUARD__', {
      value: guard.debugApi(),
      writable: false,
      configurable: false,
      enumerable: false, // 对简单枚举探针隐藏
    });
  } catch {
    /* 已存在时忽略 */
  }
}
