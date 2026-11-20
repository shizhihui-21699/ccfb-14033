/**
 * 把 src/guard 打包成单个 IIFE：public/guard/guard-bundle.js
 * IIFE 形式可直接用普通 <script> 同步加载，保证最先执行。
 */
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// 先刷新 SRI 清单（演示页完整性基线）
execFileSync(process.execPath, [resolve(root, 'scripts/gen-integrity.mjs')], {
  stdio: 'inherit',
});

await build({
  entryPoints: [resolve(root, 'src/guard/main.ts')],
  bundle: true,
  format: 'iife',
  target: ['es2020'],
  outfile: resolve(root, 'public/guard/guard-bundle.js'),
  sourcemap: true,
  legalComments: 'none',
  banner: {
    js: '/* PayGuard runtime — 必须在所有第三方脚本之前加载 */',
  },
});

console.log('[build:guard] public/guard/guard-bundle.js 已生成');
