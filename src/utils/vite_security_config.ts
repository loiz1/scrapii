/**
 * Configuración de Headers de Seguridad para Vite
 * Integración directa con vite.config.ts
 */

import type { SecurityHeaders } from './security_headers_generator';
import { getViteSecurityHeaders, validateSecurityHeaders } from './security_headers_generator';

export interface ViteSecurityConfig {
  isDevelopment: boolean;
  enableStrictCSP: boolean;
  enableHSTS: boolean;
  cspAllowedSources?: string[];
  strictMode: boolean;
}

/**
 * Configuración por defecto para producción
 */
export function createProductionSecurityConfig(): ViteSecurityConfig {
  return {
    isDevelopment: false,
    enableStrictCSP: true,
    enableHSTS: true,
    cspAllowedSources: [
      "'self'",
      "https://corsproxy.io",
      "https://aistudiocdn.com"
    ],
    strictMode: true
  };
}

/**
 * Configuración para desarrollo
 */
export function createDevelopmentSecurityConfig(): ViteSecurityConfig {
  return {
    isDevelopment: true,
    enableStrictCSP: false, // Más permisivo en desarrollo
    enableHSTS: false, // Deshabilitado en desarrollo
    cspAllowedSources: [
      "'self'",
      "'unsafe-inline'",
      "'unsafe-eval'",
      "https://corsproxy.io",
      "ws:",
      "wss:"
    ],
    strictMode: false
  };
}

/**
 * Genera configuración de headers para Vite
 */
export function generateViteSecurityHeaders(config: ViteSecurityConfig): SecurityHeaders {
  const baseHeaders = getViteSecurityHeaders(config.isDevelopment);
  
  if (config.enableStrictCSP && !config.isDevelopment) {
    baseHeaders['Content-Security-Policy'] = [
      "default-src 'self'",
      ...(config.cspAllowedSources?.map(source => `script-src ${source}`) || []),
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' https://aistudiocdn.com",
      "connect-src 'self' https://corsproxy.io",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ');
  }
  
  if (config.enableHSTS && !config.isDevelopment) {
    baseHeaders['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  } else if (config.isDevelopment) {
    baseHeaders['Strict-Transport-Security'] = 'max-age=0'; // Deshabilitado en desarrollo
  }
  
  return baseHeaders;
}

/**
 * Configuración específica para vite.config.ts
 */
export function getViteConfigHeaders(isDevelopment: boolean = false): Record<string, string> {
  const config = isDevelopment 
    ? createDevelopmentSecurityConfig()
    : createProductionSecurityConfig();
    
  const headers = generateViteSecurityHeaders(config);
  
  // Convertir a formato de Vite (Record<string, string>)
  const viteHeaders: Record<string, string> = {};
  Object.entries(headers).forEach(([key, value]) => {
    if (value) {
      viteHeaders[key] = value;
    }
  });
  
  return viteHeaders;
}

/**
 * Función para integrar en vite.config.ts
 */
export function setupSecurityHeaders(isDevelopment: boolean = false) {
  const headers = getViteConfigHeaders(isDevelopment);
  const validation = validateSecurityHeaders(headers as unknown as SecurityHeaders);
  
  if (!validation.valid) {
    console.warn('⚠️ Configuración de headers con problemas:', validation.errors);
  }
  
  return {
    headers: {
      ...headers,
      // Remover headers que exponen información
      'Server': '',
      'X-Powered-By': ''
    }
  };
}

// Ejemplo de uso en vite.config.ts:
/*
import { defineConfig } from 'vite';
import { setupSecurityHeaders } from './src/utils/vite_security_config';

export default defineConfig(({ mode }) => {
  const isDevelopment = mode === 'development';
  
  return {
    ...setupSecurityHeaders(isDevelopment),
    // ... otras configuraciones
  };
});
*/

export default {
  createProductionSecurityConfig,
  createDevelopmentSecurityConfig,
  generateViteSecurityHeaders,
  getViteConfigHeaders,
  setupSecurityHeaders
};