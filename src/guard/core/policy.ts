/**
 * PolicyEngine —— 把"请求 + 扫描命中 + 污点"转成 allow / block / report
 *
 * 判定顺序：
 *  1. 载荷命中敏感指纹
 *     - 目标服务允许该数据等级且通道/路径在允许名单内 → allow（正常业务）
 *     - 否则 → block: sensitive-fingerprint
 *  2. 没有指纹命中，但发起方读过敏感字段（污点），目标未授权该等级
 *     → block / report: taint-not-allowed（加密或拆碎载荷也逃不掉）
 *  3. 供应商被标记 blocked → block: blocked-destination
 *  4. 其余 → allow
 */
import type {
  DataClass,
  NetworkRequest,
  PolicyDecision,
  ScanHit,
  ServiceConfig,
} from '../types';
import type { ServiceRegistry } from './services';
import type { TaintRegistry } from './taint';

const CLASS_RANK: Record<DataClass, number> = { usage: 1, contact: 2, payment: 3 };

export class PolicyEngine {
  constructor(
    private services: ServiceRegistry,
    private taint: TaintRegistry,
    private selfOrigin: string,
    private blockOnTaint: boolean,
  ) {}

  private channelAllowed(svc: ServiceConfig, channel: NetworkRequest['channel']): boolean {
    if (!svc.channels || svc.channels.length === 0) return true;
    return svc.channels.includes(channel);
  }

  private pathAllowed(svc: ServiceConfig, url: string): boolean {
    if (!svc.pathAllowlist || svc.pathAllowlist.length === 0) return true;
    let path = url;
    try {
      path = new URL(url, this.selfOrigin).pathname + new URL(url, this.selfOrigin).search;
    } catch {
      /* keep raw */
    }
    return svc.pathAllowlist.some((p) => path.includes(p));
  }

  evaluate(req: NetworkRequest, hits: ScanHit[]): PolicyDecision {
    const target = this.services.resolve(req.url, this.selfOrigin);
    const initiator = this.services.get(req.initiatorService);

    // 1) 载荷里直接检出敏感数据 —— 优先判定，给出最具体的阻断原因，
    //    即使目标同时也在封禁名单上（数据泄露比单纯连黑名单更需要明确告警）
    if (hits.length > 0) {
      const maxHit = hits.reduce((a, b) =>
        CLASS_RANK[a.fingerprint.dataClass] >= CLASS_RANK[b.fingerprint.dataClass] ? a : b,
      );
      const dc = maxHit.fingerprint.dataClass;
      const targetId = target?.id ?? 'unknown';
      const allowed =
        target !== null &&
        target.dataAllowlist.includes(dc) &&
        this.channelAllowed(target, req.channel) &&
        this.pathAllowed(target, req.url);
      if (allowed) {
        return {
          verdict: 'allow',
          detail: `目标 ${targetId} 在允许名单内接收 ${dc} 数据（通道 ${req.channel}）`,
          hits,
        };
      }
      return {
        verdict: 'block',
        reason: 'sensitive-fingerprint',
        detail: `检出${dc === 'payment' ? '支付' : '联系'}数据（${maxHit.fingerprint.fieldLabel}，${maxHit.via}）发往未授权目标 ${targetId}`,
        hits,
      };
    }

    // 2) 被明确封禁的供应商（无敏感数据命中时的兜底）
    if (target?.trust === 'blocked' || initiator?.trust === 'blocked') {
      return {
        verdict: 'block',
        reason: 'blocked-destination',
        detail: `服务 ${target?.id ?? req.initiatorService} 已被配置为禁止外联`,
      };
    }

    // 2) 污点判定：发起方读过敏感字段，而目标无权接收该等级
    const taintedClass = this.taint.maxClassRead(req.initiatorService);
    if (taintedClass) {
      const targetAllowed =
        target !== null &&
        target.dataAllowlist.includes(taintedClass) &&
        this.channelAllowed(target, req.channel) &&
        this.pathAllowed(target, req.url);
      if (!targetAllowed) {
        return {
          verdict: this.blockOnTaint ? 'block' : 'report',
          reason: 'taint-not-allowed',
          detail: `发起方 ${req.initiatorService} 读取过 ${taintedClass} 级字段，但目标 ${target?.id ?? 'unknown'} 无权接收`,
        };
      }
    }

    return { verdict: 'allow', detail: '无敏感数据、无污点冲突' };
  }
}
