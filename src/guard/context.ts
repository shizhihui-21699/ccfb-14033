/**
 * 各钩子模块与 Guard 主类之间的契约
 */
import type {
  Channel,
  PolicyDecision,
  SecurityEvent,
} from './types';
import type { NativeRefs } from './core/utils';
import type { Reporter } from './core/reporter';
import type { GuardConfig } from './types';

export interface OutboundInput {
  url: string;
  channel: Channel;
  method: string;
  body: string;
}

export interface GuardApi {
  config: GuardConfig;
  refs: NativeRefs;
  reporter: Reporter;
  origin: string;

  /** 综合扫描 + 策略判定，并产出观察/阻断事件 */
  inspectOutbound(input: OutboundInput, stackFrame: string): PolicyDecision;

  /** 根据调用栈帧识别发起方服务 id */
  identifyInitiator(stackFrame: string): string;

  /** 敏感字段被读取时的污点登记 + 事件 */
  noteSensitiveRead(el: Element, stackFrame: string): void;

  /** 脚本 URL 加载校验：允许名单 + SRI 完整性 */
  checkScriptUrl(url: string): { ok: boolean; reason?: string; detail?: string };

  /** 抗关停：上报篡改行为 */
  reportTamper(detail: string, stackFrame: string): SecurityEvent;

  /** 判断某元素是否为受监控的敏感字段 */
  isWatchedField(el: Element): boolean;

  /** 标记/查询我们自己安装的事件监听器（防 removeEventListener 关停） */
  markOwnListener(fn: EventListenerOrEventListenerObject): void;
  isOwnListener(fn: EventListenerOrEventListenerObject): boolean;
}
