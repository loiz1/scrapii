/**
 * Generador de Headers de Seguridad
 * Script para configurar headers de seguridad en Vite/Express
 */

export interface SecurityHeaders {
  'Content-Security-Policy': string;
  'Strict-Transport-Security': string;
  'X-Content-Type-Options': string;
  'X-Frame-Options': string;
  'Referrer-Policy': string;
  'Permissions-Policy': string;
  'X-XSS-Protection'?: string;
  'X-Powered-By'?: string;
}

/**
 * Genera headers de seguridad básicos (mínimo seguro)
 */
export function generateBasicSecurityHeaders(): SecurityHeaders {
  return {
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  };
}

/**
 * Genera headers de seguridad avanzados (recomendado)
 */
export function generateAdvancedSecurityHeaders(): SecurityHeaders {
  return {
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://corsproxy.io",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' https://aistudiocdn.com",
      "connect-src 'self' https://corsproxy.io",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; '),
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()',
    'X-XSS-Protection': '0' // Deshabilitar el header legacy, usar CSP en su lugar
  };
}

/**
 * Headers para desarrollo (menos restrictivos)
 */
export function generateDevelopmentSecurityHeaders(): SecurityHeaders {
  return {
    'Content-Security-Policy': [
      "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://corsproxy.io",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https: blob:",
      "font-src 'self' data: https://aistudiocdn.com",
      "connect-src 'self' https://corsproxy.io ws: wss:",
      "frame-ancestors 'self'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; '),
    'Strict-Transport-Security': 'max-age=0', // Deshabilitado en desarrollo
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN', // Más permisivo para desarrollo
    'Referrer-Policy': 'no-referrer-when-downgrade',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  };
}

/**
 * Configuración para Vite
 */
export function getViteSecurityHeaders(isDevelopment: boolean = false) {
  const headers = isDevelopment 
    ? generateDevelopmentSecurityHeaders()
    : generateAdvancedSecurityHeaders();

  return headers;
}

/**
 * Configuración para Express.js
 */
export function getExpressSecurityMiddleware(isDevelopment: boolean = false) {
  const headers = getViteSecurityHeaders(isDevelopment);
  
  return (req: any, res: any, next: any) => {
    // Remover headers que exponen información
    res.removeHeader('X-Powered-By');
    
    // Establecer headers de seguridad
    Object.entries(headers).forEach(([key, value]) => {
      if (value) {
        res.setHeader(key, value);
      }
    });
    
    next();
  };
}

/**
 * Valida la configuración de headers
 */
export function validateSecurityHeaders(headers: SecurityHeaders): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Validar CSP
  if (!headers['Content-Security-Policy']) {
    errors.push('Content-Security-Policy es requerido');
  } else {
    const csp = headers['Content-Security-Policy'];
    if (!csp.includes('default-src')) {
      errors.push('CSP debe incluir default-src');
    }
  }
  
  // Validar HSTS
  if (!headers['Strict-Transport-Security']) {
    errors.push('Strict-Transport-Security es recomendado para producción');
  } else {
    const hsts = headers['Strict-Transport-Security'];
    if (!hsts.includes('max-age=')) {
      errors.push('HSTS debe incluir max-age');
    }
    if (!hsts.includes('max-age=31536000') && !hsts.includes('max-age=0')) {
      errors.push('HSTS max-age debería ser 31536000 (1 año) o 0 (deshabilitado)');
    }
  }
  
  // Validar X-Frame-Options
  if (!headers['X-Frame-Options']) {
    errors.push('X-Frame-Options es recomendado');
  } else {
    const xfo = headers['X-Frame-Options'];
    if (!['DENY', 'SAMEORIGIN', 'ALLOW-FROM'].some(val => xfo.includes(val))) {
      errors.push('X-Frame-Options debe ser DENY, SAMEORIGIN o ALLOW-FROM');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Genera reporte de implementación
 */
export function generateImplementationReport(headers: SecurityHeaders): string {
  const validation = validateSecurityHeaders(headers);
  let report = '# 🔒 Reporte de Implementación de Headers de Seguridad\n\n';
  
  report += `## 📋 Configuración Actual\n\n`;
  report += '```http\n';
  Object.entries(headers).forEach(([key, value]) => {
    if (value) {
      report += `${key}: ${value}\n`;
    }
  });
  report += '```\n\n';
  
  report += `## ✅ Estado de Validación\n\n`;
  if (validation.valid) {
    report += '✅ **Configuración válida** - Todos los headers están correctamente configurados\n\n';
  } else {
    report += '⚠️ **Configuración con problemas**:\n\n';
    validation.errors.forEach(error => {
      report += `- ${error}\n`;
    });
    report += '\n';
  }
  
  report += `## 📊 Headers Implementados\n\n`;
  const implemented = Object.keys(headers).filter(key => headers[key as keyof SecurityHeaders]);
  report += `- **Total configurados**: ${implemented.length}/${Object.keys(headers).length}\n`;
  report += `- **Headers activos**:\n`;
  implemented.forEach(header => {
    report += `  - ${header}\n`;
  });
  
  return report;
}

// Ejemplo de uso
if (require.main === module) {
  console.log('=== Headers de Seguridad - Configuración Básica ===');
  console.log(generateImplementationReport(generateBasicSecurityHeaders()));
  
  console.log('\n=== Headers de Seguridad - Configuración Avanzada ===');
  console.log(generateImplementationReport(generateAdvancedSecurityHeaders()));
  
  console.log('\n=== Headers de Seguridad - Desarrollo ===');
  console.log(generateImplementationReport(generateDevelopmentSecurityHeaders()));
}

export default {
  generateBasicSecurityHeaders,
  generateAdvancedSecurityHeaders,
  generateDevelopmentSecurityHeaders,
  getViteSecurityHeaders,
  getExpressSecurityMiddleware,
  validateSecurityHeaders,
  generateImplementationReport
};