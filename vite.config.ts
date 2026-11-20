import { defineConfig, type Plugin } from 'vite';
import { createPayguardMiddleware } from './server/payguard-middleware';

function payguardServer(): Plugin {
  return {
    name: 'payguard-server',
    configureServer(server) {
      server.middlewares.use(createPayguardMiddleware(process.cwd()));
    },
    configurePreviewServer(server) {
      server.middlewares.use(createPayguardMiddleware(process.cwd()));
    },
  };
}

export default defineConfig({
  root: '.',
  publicDir: 'public',
  plugins: [payguardServer()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
  },
  preview: {
    host: '127.0.0.1',
    port: 5199,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    target: 'es2020',
  },
});
