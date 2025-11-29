/**
 * Sistema de Scoring Inteligente de Seguridad
 * Versión 3.0 - Realistic Scoring
 * 
 * Sistema de puntuación que evalúa vulnerabilidades basándose en riesgo real
 * y impacto en la seguridad, evitando penalizaciones excesivas por headers
 * que no representan riesgos críticos.
 */

export interface SecurityScore {
  overall: number;          // Score total (0-100)
  details: ScoreDetails;    // Detalles del cálculo
  grade: string;            // Letra de calificación (A+, A, B, C, D, F)
  riskLevel: string;        // Bajo, Medio, Alto, Crítico
}

export interface ScoreDetails {
  baseline: number;         // Score base del sitio
  headers: {
    present: number;        // Puntos por headers presentes
    missing: number;        // Puntos deducidos por headers faltantes
    score: number;          // Subtotal de headers
  };
  vulnerabilities: {
    critical: number;       // Puntos deducidos por vulnerabilidades críticas
    high: number;           // Puntos deducidos por vulnerabilidades altas
    medium: number;         // Puntos deducidos por vulnerabilidades medias
    low: number;            // Puntos deducidos por vulnerabilidades bajas
    score: number;          // Subtotal de vulnerabilidades
  };
  bonus: number;            // Bonificaciones por buenas prácticas
  total: number;            // Total calculado
}

export interface SecurityHeaders {
  'content-security-policy'?: string;
  'strict-transport-security'?: string;
  'x-frame-options'?: string;
  'x-content-type-options'?: string;
  'referrer-policy'?: string;
  'permissions-policy'?: string;
  'x-xss-protection'?: string;
  [key: string]: string | undefined;
}

export interface VulnerabilityData {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export class SecurityScorer {
  // Configuración de ponderaciones realistas
  private readonly WEIGHTS = {
    // Headers de seguridad con ponderación por criticidad REAL
    HEADERS: {
      CRITICAL: 8,    // CSP, HSTS - Riesgo muy alto si falta
      HIGH: 5,        // X-Frame-Options, X-Content-Type-Options
      MEDIUM: 3,      // Referrer-Policy, Permissions-Policy
      LOW: 1          // Headers informativos
    },
    
    // Vulnerabilidades con penalización proporcional
    VULNERABILITIES: {
      CRITICAL: 25,   // API keys hardcodeadas, inyección SQL
      HIGH: 15,       // XSS, eval(), setTimeout con variables
      MEDIUM: 8,      // Inseguridades menores
      LOW: 3          // Advertencias menores
    },
    
    // Bonificaciones por buenas prácticas
    BONUS: {
      HTTPS_ENFORCEMENT: 5,
      SECURE_COOKIES: 3,
      PROPER_ERROR_HANDLING: 2,
      INPUT_VALIDATION: 4,
      OUTPUT_ENCODING: 3
    }
  };

  // Clasificación de headers por criticidad REAL
  private readonly HEADER_CRITICITY = {
    'content-security-policy': 'CRITICAL',     // Previene XSS, muy importante
    'strict-transport-security': 'CRITICAL',   // Previene MITM, crítico
    'x-frame-options': 'HIGH',                // Previene clickjacking
    'x-content-type-options': 'HIGH',         // Previene MIME sniffing
    'referrer-policy': 'MEDIUM',              // Privacidad, importante pero no crítico
    'permissions-policy': 'MEDIUM',           // Control de características
    'x-xss-protection': 'LOW'                 // Header legacy, poco relevante
  };

  // Score base para diferentes tipos de sitios
  private readonly SITE_BASELINES = {
    STATIC_SITE: 75,          // Sitios estáticos sin backend
    ECOMMERCE: 85,            // Tiendas online (más expectativas)
    ENTERPRISE: 90,           // Aplicaciones empresariales
    GOVERNMENT: 95,           // Sitios gubernamentales
    FINANCIAL: 98,            // Sitios financieros
    DEFAULT: 80              // Sitio web general
  };

  /**
   * Calcula el score de seguridad completo
   */
  public calculateScore(
    headers: SecurityHeaders,
    vulnerabilities: VulnerabilityData,
    siteType: keyof typeof this.SITE_BASELINES = 'DEFAULT'
  ): SecurityScore {
    
    // 1. Score base del sitio
    const baseline = this.SITE_BASELINES[siteType];
    
    // 2. Evaluar headers presentes
    const headersScore = this.evaluateHeaders(headers);
    
    // 3. Evaluar vulnerabilidades
    const vulnScore = this.evaluateVulnerabilities(vulnerabilities);
    
    // 4. Calcular bonificaciones
    const bonusScore = this.calculateBonusPoints(headers, vulnerabilities);
    
    // 5. Score total
    const total = Math.max(0, Math.min(100, 
      baseline + headersScore.present + vulnScore + bonusScore + headersScore.missing
    ));
    
    // 6. Determinar letra y nivel de riesgo
    const grade = this.calculateGrade(total);
    const riskLevel = this.calculateRiskLevel(total, vulnerabilities);
    
    return {
      overall: Math.round(total),
      grade,
      riskLevel,
      details: {
        baseline,
        headers: headersScore,
        vulnerabilities: {
          critical: vulnerabilities.critical,
          high: vulnerabilities.high,
          medium: vulnerabilities.medium,
          low: vulnerabilities.low,
          score: vulnScore
        },
        bonus: bonusScore,
        total
      }
    };
  }

  /**
   * Evalúa headers de seguridad con ponderación inteligente
   */
  private evaluateHeaders(headers: SecurityHeaders): { present: number; missing: number; score: number } {
    let presentPoints = 0;
    let missingPoints = 0;

    for (const [headerName, criticality] of Object.entries(this.HEADER_CRITICITY)) {
      const headerValue = headers[headerName] || headers[headerName.toLowerCase()];
      const weight = this.WEIGHTS.HEADERS[criticality as keyof typeof this.WEIGHTS.HEADERS];
      
      if (headerValue) {
        // Header presente - verificar calidad
        const qualityScore = this.evaluateHeaderQuality(headerName, headerValue);
        presentPoints += weight * qualityScore;
      } else {
        // Header faltante - penalización proporcional al riesgo
        const penaltyReduction = this.calculateMissingHeaderPenalty(headerName, criticality as any);
        missingPoints += weight * penaltyReduction;
      }
    }

    return {
      present: Math.round(presentPoints),
      missing: Math.round(missingPoints),
      score: Math.round(presentPoints + missingPoints)
    };
  }

  /**
   * Evalúa la calidad de un header específico
   */
  private evaluateHeaderQuality(headerName: string, value: string): number {
    switch (headerName) {
      case 'content-security-policy':
        return this.evaluateCSPQuality(value);
      case 'strict-transport-security':
        return this.evaluateHSTSQuality(value);
      case 'x-frame-options':
        return value.includes('DENY') || value.includes('SAMEORIGIN') ? 1.0 : 0.7;
      default:
        return value ? 1.0 : 0.0;
    }
  }

  /**
   * Evalúa la calidad de la política CSP
   */
  private evaluateCSPQuality(cspValue: string): number {
    const goodPractices = ['default-src', 'script-src', 'style-src'];
    const hasNonces = cspValue.includes('nonce-') || cspValue.includes('sha256-');
    const hasUnsafeInline = cspValue.includes("'unsafe-inline'");
    
    let score = 0.5; // Base score
    
    // Puntos por directivas básicas
    goodPractices.forEach(directive => {
      if (cspValue.includes(directive)) score += 0.2;
    });
    
    // Bonus por no usar 'unsafe-inline'
    if (!hasUnsafeInline) score += 0.3;
    
    // Bonus por usar nonces/sha256
    if (hasNonces) score += 0.2;
    
    return Math.min(1.0, score);
  }

  /**
   * Evalúa la calidad de HSTS
   */
  private evaluateHSTSQuality(hstsValue: string): number {
    const hasMaxAge = hstsValue.includes('max-age=');
    const hasIncludeSubDomains = hstsValue.includes('includeSubDomains');
    const hasPreload = hstsValue.includes('preload');
    
    let score = 0.3; // Base score si tiene max-age
    
    if (hasMaxAge) score += 0.3;
    if (hasIncludeSubDomains) score += 0.2;
    if (hasPreload) score += 0.2;
    
    return Math.min(1.0, score);
  }

  /**
   * Calcula la penalización por header faltante considerando el contexto
   */
  private calculateMissingHeaderPenalty(headerName: string, criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): number {
    // Headers que son menos críticos en ciertos contextos
    const contextReduction = {
      'x-xss-protection': 0.3, // Header legacy, menos importante
      'referrer-policy': 0.5,  // Importante pero no crítico
      'permissions-policy': 0.4 // Control granular, no es obligatorio
    };
    
    const reduction = contextReduction[headerName as keyof typeof contextReduction] || 1.0;
    return reduction;
  }

  /**
   * Evalúa vulnerabilidades con penalización proporcional
   */
  private evaluateVulnerabilities(vulns: VulnerabilityData): number {
    let totalPenalty = 0;
    
    // Penalización por vulnerabilidades críticas (pero no devastadora)
    if (vulns.critical > 0) {
      totalPenalty += this.WEIGHTS.VULNERABILITIES.CRITICAL * Math.min(vulns.critical, 3);
    }
    
    // Penalización por vulnerabilidades altas
    if (vulns.high > 0) {
      totalPenalty += this.WEIGHTS.VULNERABILITIES.HIGH * Math.min(vulns.high, 5);
    }
    
    // Penalización por vulnerabilidades medias
    if (vulns.medium > 0) {
      totalPenalty += this.WEIGHTS.VULNERABILITIES.MEDIUM * Math.min(vulns.medium, 8);
    }
    
    // Penalización por vulnerabilidades bajas
    if (vulns.low > 0) {
      totalPenalty += this.WEIGHTS.VULNERABILITIES.LOW * Math.min(vulns.low, 10);
    }
    
    return -Math.round(totalPenalty);
  }

  /**
   * Calcula bonificaciones por buenas prácticas
   */
  private calculateBonusPoints(headers: SecurityHeaders, vulnerabilities: VulnerabilityData): number {
    let bonus = 0;
    
    // Bonificación por HTTPS enforcement
    if (headers['strict-transport-security']?.includes('max-age')) {
      bonus += this.WEIGHTS.BONUS.HTTPS_ENFORCEMENT;
    }
    
    // Bonificación por baja cantidad de vulnerabilidades
    const totalVulns = vulnerabilities.critical + vulnerabilities.high + vulnerabilities.medium + vulnerabilities.low;
    if (totalVulns === 0) {
      bonus += 3;
    } else if (totalVulns <= 2) {
      bonus += 1;
    }
    
    return bonus;
  }

  /**
   * Calcula la letra de calificación
   */
  private calculateGrade(score: number): string {
    if (score >= 95) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 85) return 'A-';
    if (score >= 80) return 'B+';
    if (score >= 75) return 'B';
    if (score >= 70) return 'B-';
    if (score >= 65) return 'C+';
    if (score >= 60) return 'C';
    if (score >= 55) return 'C-';
    if (score >= 50) return 'D';
    return 'F';
  }

  /**
   * Calcula el nivel de riesgo
   */
  private calculateRiskLevel(score: number, vulnerabilities: VulnerabilityData): string {
    const hasCriticalVulns = vulnerabilities.critical > 0;
    const hasHighVulns = vulnerabilities.high > 0;
    
    if (score >= 85 && !hasCriticalVulns && vulnerabilities.high <= 1) return 'Bajo';
    if (score >= 70 && !hasCriticalVulns) return 'Medio';
    if (score >= 50 || vulnerabilities.high > 2) return 'Alto';
    return 'Crítico';
  }

  /**
   * Genera un reporte detallado del score
   */
  public generateDetailedReport(score: SecurityScore): string {
    const { details } = score;
    
    let report = `# 🔒 Informe de Score de Seguridad\n`;
    report += `## Score General: ${score.overall}/100 (${score.grade})\n`;
    report += `## Nivel de Riesgo: ${score.riskLevel}\n\n`;
    
    report += `## 📊 Desglose Detallado\n\n`;
    report += `### Baseline del Sitio: ${details.baseline}pts\n`;
    report += `### Headers de Seguridad: ${details.headers.present - Math.abs(details.headers.missing)}pts\n`;
    report += `  - Presentes: +${details.headers.present}pts\n`;
    report += `  - Faltantes: ${details.headers.missing}pts\n`;
    report += `### Vulnerabilidades: ${details.vulnerabilities}pts\n`;
    report += `### Bonificaciones: +${details.bonus}pts\n`;
    report += `### **TOTAL: ${details.total}pts**\n\n`;
    
    report += `## 🎯 Recomendaciones\n\n`;
    
    if (score.overall >= 90) {
      report += `✅ **Excelente nivel de seguridad**\n`;
      report += `   - Mantener buenas prácticas actuales\n`;
      report += `   - Monitorear nuevas amenazas\n`;
    } else if (score.overall >= 75) {
      report += `✅ **Buen nivel de seguridad con áreas de mejora**\n`;
      report += `   - Implementar headers faltantes de alta prioridad\n`;
      report += `   - Revisar y corregir vulnerabilidades existentes\n`;
    } else if (score.overall >= 60) {
      report += `⚠️ **Seguridad mejorable - requiere atención**\n`;
      report += `   - Priorizar corrección de vulnerabilidades altas\n`;
      report += `   - Implementar headers de seguridad faltantes\n`;
    } else {
      report += `🚨 **Seguridad insuficiente - acción urgente requerida**\n`;
      report += `   - Corregir todas las vulnerabilidades críticas\n`;
      report += `   - Implementar todas las medidas de seguridad básicas\n`;
    }
    
    return report;
  }
}