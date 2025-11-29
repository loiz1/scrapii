/**
 * Utilitarios de Seguridad para Sanitización de Entrada
 * Previene XSS y otros ataques de inyección
 */

export interface SanitizedInput {
  original: string;
  sanitized: string;
  isSafe: boolean;
  warnings: string[];
}

/**
 * Sanitiza entrada de usuario para prevenir XSS
 */
export function sanitizeUserInput(input: string, maxLength: number = 1000): SanitizedInput {
  const warnings: string[] = [];
  let sanitized = input.trim();
  
  // Validar longitud
  if (sanitized.length > maxLength) {
    warnings.push(`Input truncado de ${sanitized.length} a ${maxLength} caracteres`);
    sanitized = sanitized.substring(0, maxLength);
  }

  // Patrones peligrosos a detectar
  const dangerousPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /eval\s*\(/gi,
    /expression\s*\(/gi,
    /vbscript:/gi,
    /data:/gi
  ];

  let isSafe = true;
  dangerousPatterns.forEach((pattern, index) => {
    if (pattern.test(sanitized)) {
      isSafe = false;
      warnings.push(`Patrón peligroso detectado: ${pattern.source}`);
      // Remover el patrón peligroso
      sanitized = sanitized.replace(pattern, '');
    }
  });

  // Validar URL si parece ser una URL
  if (sanitized.match(/^https?:\/\//i)) {
    try {
      const url = new URL(sanitized);
      // Solo permitir ciertos protocolos
      if (!['http:', 'https:'].includes(url.protocol)) {
        isSafe = false;
        warnings.push('Protocolo no permitido en URL');
        sanitized = '';
      }
    } catch {
      isSafe = false;
      warnings.push('URL malformada detectada');
    }
  }

  // Escapar HTML remaining
  sanitized = sanitized
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

  return {
    original: input,
    sanitized,
    isSafe: isSafe && sanitized.length > 0,
    warnings
  };
}

/**
 * Valida si una URL es segura para scraping
 */
export function validateScrapingUrl(url: string): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  try {
    const urlObj = new URL(url);
    
    // Validar protocolo
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      errors.push('Solo se permiten protocolos HTTP y HTTPS');
    }
    
    // Validar longitud
    if (url.length > 2048) {
      errors.push('URL demasiado larga');
    }
    
    // Detectar URLs potencialmente maliciosas
    const suspiciousPatterns = [
      /localhost/i,
      /127\.0\.0\.1/,
      /0\.0\.0\.0/,
      /10\./,
      /192\.168\./,
      /172\.(1[6-9]|2\d|3[0-1])\./,
      /file:/i,
      /ftp:/i
    ];
    
    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(url)) {
        errors.push('URL potencialmente insegura detectada');
      }
    });
    
  } catch {
    errors.push('URL malformada');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Genera Content Security Policy headers
 */
export function generateCSPHeader(): string {
  return [
    "default-src 'self'",
    "script-src 'self' https://aistudiocdn.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' https://aistudiocdn.com",
    "connect-src 'self' https://corsproxy.io",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ');
}

/**
 * Análisis de riesgos de seguridad
 */
export interface SecurityAnalysis {
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  issues: string[];
  recommendations: string[];
  score: number; // 0-100
}

export function performSecurityAnalysis(input: string, context: 'url' | 'general' = 'general'): SecurityAnalysis {
  const issues: string[] = [];
  const recommendations: string[] = [];
  let score = 100;
  
  // Análisis de longitud
  if (input.length > 1000) {
    issues.push('Input excesivamente largo');
    score -= 10;
  }
  
  // Análisis de caracteres especiales
  const specialCharCount = (input.match(/[<>\"'&]/g) || []).length;
  if (specialCharCount > 10) {
    issues.push('Exceso de caracteres especiales');
    score -= 15;
  }
  
  // Análisis de patrones específicos según contexto
  if (context === 'url') {
    const urlAnalysis = validateScrapingUrl(input);
    if (!urlAnalysis.isValid) {
      issues.push(...urlAnalysis.errors);
      score -= 30;
    }
  }
  
  // Detectar inyección de código
  const codeInjectionPatterns = [
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /eval\s*\(/i,
    /expression\s*\(/i
  ];
  
  codeInjectionPatterns.forEach(pattern => {
    if (pattern.test(input)) {
      issues.push('Posible inyección de código detectada');
      score -= 50;
    }
  });
  
  // Generar recomendaciones
  if (issues.length === 0) {
    recommendations.push('Input pasa validaciones de seguridad');
  } else {
    recommendations.push('Implementar sanitización adicional');
    recommendations.push('Validar entrada en backend');
    recommendations.push('Usar whitelists en lugar de blacklists');
  }
  
  // Determinar nivel de riesgo
  let riskLevel: SecurityAnalysis['riskLevel'] = 'low';
  if (score < 70) riskLevel = 'medium';
  if (score < 50) riskLevel = 'high';
  if (score < 30) riskLevel = 'critical';
  
  return {
    riskLevel,
    issues,
    recommendations,
    score: Math.max(score, 0)
  };
}