/**
 * TaintRegistry —— 记录"谁在什么时候读取了哪个敏感输入框"
 * 读取污点是外发判定的第二道证据（即使载荷被加密/拆碎扫描不到，
 * 只要读过支付字段的供应商把数据发到了未授权目标，照样阻断）。
 */
import type { DataClass, TaintRecord } from '../types';

export class TaintRegistry {
  private records = new Map<string, TaintRecord>();
  /** 同一服务读同一字段的节流，避免每次 keystroke 都产生事件 */
  private throttleMs = 4000;

  noteRead(serviceId: string, fieldLabel: string, dataClass: DataClass, stackFrame: string): TaintRecord | null {
    const key = `${serviceId}|${fieldLabel}`;
    const now = Date.now();
    const prev = this.records.get(key);
    if (prev && now - prev.at < this.throttleMs) return null;
    const rec: TaintRecord = { serviceId, fieldLabel, dataClass, at: now, stackFrame };
    this.records.set(key, rec);
    return rec;
  }

  /** 某服务读取过的最高敏感等级 */
  maxClassRead(serviceId: string): DataClass | null {
    let max: DataClass | null = null;
    for (const rec of this.records.values()) {
      if (rec.serviceId !== serviceId) continue;
      if (rec.dataClass === 'payment') return 'payment';
      if (rec.dataClass === 'contact') max = 'contact';
      else if (!max) max = rec.dataClass;
    }
    return max;
  }

  listByService(serviceId: string): TaintRecord[] {
    return [...this.records.values()].filter((r) => r.serviceId === serviceId);
  }

  snapshot(): TaintRecord[] {
    return [...this.records.values()];
  }
}
