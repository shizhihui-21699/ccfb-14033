/**
 * 扫描 public/vendor 下的合法供应商脚本，计算 SHA-384 SRI，
 * 生成 src/app/integrity.generated.ts 供演示页注入 PayGuard 配置。
 *
 * 被篡改样本（*.tampered.js、malware/、unknown/）不纳入完整性基线。
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const vendorDir = join(root, 'public/vendor');

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...walk(full));
    } else if (entry.endsWith('.js')) {
      out.push(full);
    }
  }
  return out;
}

const files = walk(vendorDir).filter((f) => {
  const rel = relative(vendorDir, f).replaceAll('\\', '/');
  return !rel.includes('.tampered.') && !rel.startsWith('malware/') && !rel.startsWith('unknown/');
});

const manifest = files
  .map((f) => {
    const hash = createHash('sha384').update(readFileSync(f)).digest('base64');
    const webPath = '/' + relative(join(root, 'public'), f).replaceAll('\\', '/');
    return `  { src: '${webPath}', integrity: 'sha384-${hash}' }`;
  })
  .join(',\n');

const content = `// 由 scripts/gen-integrity.mjs 自动生成，请勿手改
export const integrityManifest: { src: string; integrity: string }[] = [
${manifest}
];
`;

writeFileSync(join(root, 'src/app/integrity.generated.ts'), content);
console.log(`[gen-integrity] 已为 ${files.length} 个合法供应商脚本生成 SRI 清单`);
