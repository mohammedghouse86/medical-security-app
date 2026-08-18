import { copyFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// GitHub Pages serves static files only, so deep links like /dashboard match no
// file and get GitHub's own 404. Pages falls back to 404.html for any missing
// path, so shipping a copy of the built index.html under that name hands the
// request to the client-side router with the original URL intact.
const spaFallback = () => {
  let outDir;
  return {
    name: 'spa-404-fallback',
    apply: 'build',
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir);
    },
    closeBundle() {
      copyFileSync(resolve(outDir, 'index.html'), resolve(outDir, '404.html'));
    }
  };
};

export default defineConfig({
  plugins: [react(), spaFallback()],
  // GitHub Pages project sites are served from /REPOSITORY_NAME/
  // Change this value if your repository name is different.
  base: '/medical-security-app/',
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: ['.trycloudflare.com'],
    proxy: {
      '/api': {
        target: 'http://localhost:4000',
        changeOrigin: true
      }
    }
  }
});
