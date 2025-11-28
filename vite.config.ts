import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// Plugin para eliminar console.log statements en producción
function removeConsolePlugin() {
  return {
    name: 'remove-console',
    transform(code: string, id: string) {
      if (process.env.NODE_ENV === 'production') {
        // Remover console.log, console.info, console.warn en producción
        code = code.replace(/console\.(log|info|warn)\([^;]*\);?/g, '');
        // Mantener console.error para debugging crítico
      }
      return code;
    }
  };
}

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, '.', '');
    return {
      server: {
        port: 3000,
        host: '0.0.0.0',
        headers: {
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
      },
      plugins: [react(), removeConsolePlugin()],
      define: {
        'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
        'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
        }
      },
      build: {
        // Configuraciones de seguridad para producción
        minify: 'terser',
        terserOptions: {
          compress: {
            drop_console: true,
            drop_debugger: true,
            pure_funcs: ['console.log', 'console.info', 'console.warn']
          }
        },
        rollupOptions: {
          output: {
            // Configurar headers de seguridad
            assetFileNames: '[name].[hash][extname]',
            chunkFileNames: '[name].[hash].js',
            entryFileNames: '[name].[hash].js'
          }
        }
      }
    };
});
