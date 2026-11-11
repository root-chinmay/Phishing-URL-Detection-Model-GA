import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import type { Plugin } from 'vite';
import { defineConfig } from 'vite';
import { resolveRedirectChainNode } from './src/server/urlResolver';

function urlResolverMiddlewarePlugin(): Plugin {
  const attachMiddleware = (middlewares: any) => {
    middlewares.use('/api/resolve-url', async (req: any, res: any, next: any) => {
      if (req.method !== 'POST' && req.method !== 'GET') {
        return next();
      }
      try {
        let targetUrl = '';
        if (req.method === 'GET') {
          const parsedReqUrl = new URL(req.url || '', 'http://localhost');
          targetUrl = parsedReqUrl.searchParams.get('url') || '';
        } else {
          const chunks: Buffer[] = [];
          for await (const chunk of req) {
            chunks.push(Buffer.from(chunk));
          }
          const rawBody = Buffer.concat(chunks).toString('utf-8');
          const parsedBody = rawBody ? JSON.parse(rawBody) : {};
          targetUrl = parsedBody.url || '';
        }

        if (!targetUrl.trim()) {
          res.statusCode = 400;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ error: 'Missing url parameter' }));
          return;
        }

        const result = await resolveRedirectChainNode(targetUrl);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(result));
      } catch (err) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          error: err instanceof Error ? err.message : 'Failed to resolve URL',
          resolved: false
        }));
      }
    });
  };

  return {
    name: 'url-resolver-api',
    configureServer(server) {
      attachMiddleware(server.middlewares);
    },
    configurePreviewServer(server) {
      attachMiddleware(server.middlewares);
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), urlResolverMiddlewarePlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
