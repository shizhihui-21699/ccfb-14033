/**
 * PayGuard 核心类型定义
 */

/** 数据敏感等级 */
export type DataClass = 'payment' | 'contact' | 'usage';

/** 供应商信任级别 */
export type TrustLevel = 'trusted' | 'observed' | 'blocked';

/** 网络外发通道 */
export type Channel =
  | 'fetch'
  | 'xhr'
  | 'beacon'
  | 'image'
  | 'font'
  | 'websocket'
  | 'eventsource'
  | 'navigation'
  | 'link'
  | 'css'
  | 'script-load';

/** 阻断原因 */
export type BlockReason =
  | 'sensitive-fingerprint'      // 载荷中直接命中敏感数据指纹
  | 'taint-not-allowed'          // 读过敏感字段的供应商向未授权目标发数据
  | 'unauthorized-script'        // 不在允许名单内的脚本加载
  | 'integrity-mismatch'         // SRI 完整性校验失败（脚本被篡改）
  | 'guard-tamper'               // 试图关停 / 篡改防护
  | 'blocked-destination';       // 供应商被配置为完全禁止外联

export type Verdict = 'allow' | 'block' | 'report';

/** 敏感输入框定义 */
export interface SensitiveFieldDef {
  /** 匹配 input 的 name / id / autocomplete / data-pg 属性，小写包含匹配 */
  match: string[];
  dataClass: DataClass;
  label: string;
}

/** 供应商 / 外联目标服务配置 */
export interface ServiceConfig {
  id: string;
  /** 主机名或脚本路径前缀（脚本加载允许名单也用它） */
  origins: string[];
  trust: TrustLevel;
  /** 允许外发的数据等级 */
  dataAllowlist: DataClass[];
  /** 允许使用的外发通道，缺省表示全部允许 */
  channels?: Channel[];
  /** 允许上报到的路径子串（针对同源请求的细化控制） */
  pathAllowlist?: string[];
  label: string;
}

/** 带 SRI 的受保护脚本 */
export interface ProtectedScript {
  src: string;
  integrity: string; // 形如 sha384-xxxx
}

export interface GuardConfig {
  /** 服务端上报地址（同源），空串表示仅页面内事件总线 */
  reportEndpoint: string;
  services: ServiceConfig[];
  sensitiveFields: SensitiveFieldDef[];
  /** 脚本完整性（SRI）清单 */
  protectedScripts?: ProtectedScript[];
  /** 读过支付字段即向未授权目标外发时是否阻断（false = 仅上报） */
  blockOnTaint: boolean;
  /** 心跳校验周期 ms */
  heartbeatMs: number;
  /** 是否在控制台输出调试信息 */
  debug: boolean;
}

/** 一次读取敏感字段的污点记录 */
export interface TaintRecord {
  serviceId: string;
  fieldLabel: string;
  dataClass: DataClass;
  at: number;
  stackFrame: string;
}

/** 敏感数据指纹 */
export interface SecretFingerprint {
  /** 原始值，用于精确比对 */
  exact: string;
  /** 去掉空格/连字符后的形式，用于对付 4242-4242 这类变形 */
  compact: string;
  /** 末四位（部分掩码场景） */
  last4?: string;
  dataClass: DataClass;
  fieldLabel: string;
}

/** 外发请求的归一化描述 */
export interface NetworkRequest {
  url: string;
  channel: Channel;
  method: string;
  /** 字符串化后的请求体（拿不到时为空） */
  body: string;
  /** 发起方调用栈（首个外部脚本帧） */
  stackFrame: string;
  /** 发起方服务 id（无法识别为 unknown） */
  initiatorService: string;
}

/** 扫描命中的敏感数据 */
export interface ScanHit {
  fingerprint: SecretFingerprint;
  /** 命中的具体字符串形式 */
  matched: string;
  /** 解码方式 */
  via: string;
}

export interface PolicyDecision {
  verdict: Verdict;
  reason?: BlockReason;
  /** 命中的服务 id / 指纹说明 */
  detail: string;
  hits?: ScanHit[];
}

/** 上报给服务端 / 页面总线的安全事件 */
export interface SecurityEvent {
  id: string;
  ts: number;
  kind: 'block' | 'alert' | 'observation' | 'tamper';
  channel?: Channel;
  reason?: BlockReason;
  serviceId: string;
  targetUrl?: string;
  fieldLabel?: string;
  dataClass?: DataClass;
  detail: string;
  stackFrame: string;
  /** 截断后的请求体片段，绝不包含完整卡号（只放脱敏片段） */
  payloadPreview?: string;
}

export type EventListener = (e: SecurityEvent) => void;
