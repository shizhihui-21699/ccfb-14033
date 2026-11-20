/**
 * Playwright 配置：每个测试完全隔离的浏览器上下文，
 * 杜绝前一个测试页面里的延迟攻击定时器、存储状态泄漏到后续测试。
 */
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts',
  timeout: 90000,
  fullyParallel: false,
  workers: 1,
  retries: 1,
  use: {
    baseURL: 'http://127.0.0.1:5199',
    headless: true,
    navigationTimeout: 30000,
    actionTimeout: 20000,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run build && npm run preview -- --port 5199 --strictPort',
    url: 'http://127.0.0.1:5199/',
    timeout: 120000,
    reuseExistingServer: true,
  },
});
