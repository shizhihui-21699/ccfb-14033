/**
 * PayGuard 上报接收中间件，dev 与 preview 模式共用。
 *  - POST /payguard/events：收集事件
 *  - GET  /payguard/events：SSE 实时推送
 *  - GET  /payguard/snapshot：已收集事件
 *  - GET  /vendor/_tampered/*：SRI 篡改演示路由
 */
import type { Connect } from 'vite';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const events: unknown[] = [];
const sseClients = new Set<(data: string) => void>();

export function createPayguardMiddleware(root: string): Connect.HandleFunction {
  return (req: IncomingMessage, res: ServerResponse, next: Connect.NextFunction) => {
    const url = req.url ?? '';

    if (url.startsWith('/payguard/events')) {
      if (req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        });
        const send = (data: string) => res.write(`data: ${data}\n\n`);
        sseClients.add(send);
        send(JSON.stringify({ hello: true, count: events.length }));
        req.on('close', () => sseClients.delete(send));
        return;
      }
      if (req.method === 'POST') {
        let body = '';
        req.on('data', (chunk: Buffer) => (body += chunk));
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body) as { events?: unknown[] };
            for (const evt of parsed.events ?? []) {
              events.push(evt);
              sseClients.forEach((send) => send(JSON.stringify(evt)));
            }
            if (events.length > 500) events.splice(0, events.length - 500);
          } catch {
            /* 忽略坏数据 */
          }
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ ok: true, total: events.length }));
        });
        return;
      }
      res.statusCode = 405;
      res.end();
      return;
    }

    if (url.startsWith('/payguard/snapshot')) {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ events }));
      return;
    }

    if (url.startsWith('/vendor/_tampered')) {
      const name = url.replace('/vendor/_tampered', '').split('?')[0]!.replace(/^\//, '');
      const file = resolve(root, 'dist/vendor', name);
      if (!existsSync(file)) {
        res.statusCode = 404;
        res.end();
        return;
      }
      const original = readFileSync(file, 'utf8');
      res.setHeader('content-type', 'application/javascript');
      res.end(
        `${original}\n//# tampered-at-server: 这段内容是中间人/被入侵 CDN 注入的\nconsole.log('恶意代码已执行');\n`,
      );
      return;
    }

    next();
  };
}
