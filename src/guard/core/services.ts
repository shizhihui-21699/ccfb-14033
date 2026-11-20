/**
 * ServiceRegistry —— 供应商/外联目标身份识别
 * 用主机名 + 路径前缀把 URL 映射到配置里的服务；同源请求映射到 self。
 */
import type { ServiceConfig } from '../types';

export class ServiceRegistry {
  constructor(private services: ServiceConfig[]) {}

  /**
   * 识别 URL 属于哪个服务。
   * @param selfOrigin 当前页面 origin（同源请求归一为 self）
   */
  resolve(url: string, selfOrigin: string): ServiceConfig | null {
    let host = '';
    let path = '';
    try {
      const u = new URL(url, selfOrigin);
      host = u.host;
      path = u.pathname;
      if (u.origin === selfOrigin) {
        // 同源：再看路径是否落在某个供应商的挂载路径下（例如 /vendor/analytics/）
        const byPath = this.services.find((s) =>
          s.origins.some((o) => o.startsWith('/') && path.startsWith(o)),
        );
        return byPath ?? this.services.find((s) => s.id === 'self') ?? null;
      }
    } catch {
      host = url;
      path = '';
    }
    // 主机名匹配（支持子域：metrics.ads.example.com 命中 .example.com 风格配置）
    const byHost = this.services.find((s) =>
      s.origins.some((o) => {
        if (o.startsWith('/')) return false;
        if (o.startsWith('.')) return host === o.slice(1) || host.endsWith(o);
        return host === o || host.endsWith(`.${o}`);
      }),
    );
    if (byHost) return byHost;
    // 再退回路径前缀匹配
    const byPath = this.services.find((s) =>
      s.origins.some((o) => o.startsWith('/') && path.startsWith(o)),
    );
    return byPath ?? null;
  }

  get(id: string): ServiceConfig | null {
    return this.services.find((s) => s.id === id) ?? null;
  }

  all(): ServiceConfig[] {
    return this.services;
  }

  /**
   * 脚本加载授权判定（比 resolve 更严格）：
   * 同源 URL 只有命中某个供应商的挂载路径、或显式 self 路径前缀才算授权，
   * 绝不因为"同源"就放行任意路径的脚本（防止 /vendor/unknown 这类注入）。
   */
  isAuthorizedScript(url: string, selfOrigin: string, extraPrefixes: string[]): boolean {
    if (extraPrefixes.some((p) => url.startsWith(p))) return true;
    let path = url;
    let isSameOrigin = false;
    try {
      const u = new URL(url, selfOrigin);
      path = u.pathname;
      isSameOrigin = u.origin === selfOrigin;
    } catch {
      /* 保持原值 */
    }
    // 命中任何配置的路径前缀即授权
    const pathHit = this.services.some((s) =>
      s.origins.some((o) => o.startsWith('/') && path.startsWith(o)),
    );
    if (pathHit) return true;
    // 跨源脚本：主机名命中某个供应商即授权
    if (!isSameOrigin) {
      return this.resolve(url, selfOrigin) !== null;
    }
    // 同源但未命中任何供应商路径前缀：拒绝
    return false;
  }
}
