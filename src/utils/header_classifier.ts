/**
 * Clasificador de Headers de Seguridad por Criticidad Real
 * Versión 3.0 - Realistic Risk Assessment
 * 
 * Sistema que clasifica headers de seguridad basándose en el riesgo REAL
 * que representan para la seguridad, evitando penalizaciones excesivas
 * por headers que no son críticos en todos los contextos.
 */

export interface HeaderClassification {
  name: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  impact: string;
  description: string;
  score: number; // Puntos asignados
  contextModifiers: ContextModifier[];
  legacyStatus: 'ACTIVE' | 'DEPRECATED' | 'OBSOLETE';
  browserSupport: string;
  mitigationEffectiveness: number; // 0-1, qué tan efectivo es
}

export interface ContextModifier {
  context: string;
  modifier: number; // Multiplicador del score (0.1 = 10% del score original)
  reason: string;
}

export class SecurityHeaderClassifier {
  private readonly CLASSIFICATIONS: HeaderClassification[] = [
    {
      name: 'content-security-policy',
      criticality: 'CRITICAL',
      impact: 'Prevención de XSS y inyección de contenido',
      description: 'La política CSP es fundamental para prevenir ataques XSS al controlar qué fuentes de contenido están permitidas.',
      score: 25,
      contextModifiers: [
        {
          context: 'static-site',
          modifier: 0.3,
          reason: 'Sitios estáticos con poco JavaScript dinámico tienen menos riesgo'
        },
        {
          context: 'ecommerce',
          modifier: 1.0,
          reason: 'E-commerce requiere protección máxima contra XSS'
        },
        {
          context: 'single-page-app',
          modifier: 0.8,
          reason: 'SPAs necesitan CSP bien configurado pero pueden ser más flexibles'
        }
      ],
      legacyStatus: 'ACTIVE',
      browserSupport: 'Excelente (IE11+, todos los navegadores modernos)',
      mitigationEffectiveness: 0.95
    },
    {
      name: 'strict-transport-security',
      criticality: 'CRITICAL',
      impact: 'Prevención de ataques man-in-the-middle y downgrade HTTPS',
      description: 'Fuerza el uso de HTTPS y previene ataques de downgrade HTTP.',
      score: 20,
      contextModifiers: [
        {
          context: 'no-ssl',
          modifier: 0.0,
          reason: 'Si no hay SSL, HSTS no aplica'
        },
        {
          context: 'mixed-content',
          modifier: 0.2,
          reason: 'Sitios con contenido mixto no pueden usar HSTS efectivamente'
        },
        {
          context: 'api-only',
          modifier: 0.6,
          reason: 'APIs son menos vulnerables a downgrade attacks'
        }
      ],
      legacyStatus: 'ACTIVE',
      browserSupport: 'Excelente (IE11+, todos los navegadores modernos)',
      mitigationEffectiveness: 0.98
    },
    {
      name: 'x-frame-options',
      criticality: 'HIGH',
      impact: 'Prevención de clickjacking',
      description: 'Previene que el sitio sea embebido en iframes maliciosos.',
      score: 15,
      contextModifiers: [
        {
          context: 'embeddable',
          modifier: 0.0,
          reason: 'Sitios diseñados para ser embebidos no pueden usar DENY/SAMEORIGIN'
        },
        {
          context: 'iframe-widget',
          modifier: 0.0,
          reason: 'Widgets que deben ser iframed no aplican'
        },
        {
          context: 'standalone',
          modifier: 1.0,
          reason: 'Sitios standalone se benefician completamente'
        }
      ],
      legacyStatus: 'ACTIVE',
      browserSupport: 'Bueno (IE8+, todos los navegadores modernos)',
      mitigationEffectiveness: 0.85
    },
    {
      name: 'x-content-type-options',
      criticality: 'HIGH',
      impact: 'Prevención de MIME sniffing attacks',
      description: 'Previene que el navegador adivine el tipo MIME de archivos.',
      score: 12,
      contextModifiers: [
        {
          context: 'static-content',
          modifier: 0.8,
          reason: 'Contenido estático tiene menor riesgo'
        },
        {
          context: 'dynamic-content',
          modifier: 1.0,
          reason: 'Contenido dinámico requiere protección completa'
        }
      ],
      legacyStatus: 'ACTIVE',
      browserSupport: 'Excelente (IE8+, todos los navegadores modernos)',
      mitigationEffectiveness: 0.75
    },
    {
      name: 'referrer-policy',
      criticality: 'MEDIUM',
      impact: 'Privacidad - control de información de referrer',
      description: 'Controla cuánta información de referrer se envía con las solicitudes.',
      score: 8,
      contextModifiers: [
        {
          context: 'privacy-focused',
          modifier: 1.2,
          reason: 'Sitios enfocados en privacidad valoran esto más'
        },
        {
          context: 'analytics-required',
          modifier: 0.3,
          reason: 'Si se requiere analytics detallado, esto puede ser conflictivo'
        },
        {
          context: 'internal-only',
          modifier: 0.5,
          reason: 'Aplicaciones internas tienen menor impacto'
        }
      ],
      legacyStatus: 'ACTIVE',
      browserSupport: 'Bueno (Chrome 70+, Firefox 70+, Safari 11+)',
      mitigationEffectiveness: 0.60
    },
    {
      name: 'permissions-policy',
      criticality: 'MEDIUM',
      impact: 'Control granular de características del navegador',
      description: 'Controla el acceso a características del navegador como cámara, micrófono, etc.',
      score: 6,
      contextModifiers: [
        {
          context: 'mobile-app',
          modifier: 0.4,
          reason: 'Aplicaciones móviles tienen menos exposición'
        },
        {
          context: 'enterprise',
          modifier: 1.1,
          reason: 'Empresas valoran el control granular'
        },
        {
          context: 'public-site',
          modifier: 0.7,
          reason: 'Sitios públicos pueden ser más permisivos'
        }
      ],
      legacyStatus: 'ACTIVE',
      browserSupport: 'Moderado (Chrome 88+, Firefox 91+, Safari 16+)',
      mitigationEffectiveness: 0.50
    },
    {
      name: 'x-xss-protection',
      criticality: 'LOW',
      impact: 'Filtro XSS legacy del navegador (obsoleto)',
      description: 'Header legacy que activa el filtro XSS de IE. Ya no es relevante.',
      score: 3,
      contextModifiers: [
        {
          context: 'legacy-browser',
          modifier: 1.5,
          reason: 'Solo relevante para navegadores antiguos'
        },
        {
          context: 'modern-browser',
          modifier: 0.1,
          reason: 'Navegadores modernos usan CSP en su lugar'
        },
        {
          context: 'ie-support',
          modifier: 0.0,
          reason: 'No aplica si no se soporta IE'
        }
      ],
      legacyStatus: 'DEPRECATED',
      browserSupport: 'Solo IE (obsoleto)',
      mitigationEffectiveness: 0.20
    },
    {
      name: 'expect-ct',
      criticality: 'LOW',
      impact: 'Transparency Certificate enforcement',
      description: 'Header para Certificate Transparency. Ya no es necesario con Certificate Transparency 2.',
      score: 2,
      contextModifiers: [
        {
          context: 'certificate-transparency',
          modifier: 0.8,
          reason: 'Solo relevante para organizaciones que requieren CT'
        }
      ],
      legacyStatus: 'DEPRECATED',
      browserSupport: 'Limitado (Chrome, Edge)',
      mitigationEffectiveness: 0.30
    }
  ];

  /**
   * Obtiene la clasificación de un header específico
   */
  public getHeaderClassification(headerName: string): HeaderClassification | null {
    const normalizedName = headerName.toLowerCase().replace(/-/g, '-');
    return this.CLASSIFICATIONS.find(h => 
      h.name.toLowerCase() === normalizedName
    ) || null;
  }

  /**
   * Calcula el score ajustado para un header en un contexto específico
   */
  public calculateAdjustedScore(headerName: string, context: string): number {
    const classification = this.getHeaderClassification(headerName);
    if (!classification) return 0;

    const modifier = classification.contextModifiers.find(m => m.context === context);
    return modifier ? Math.round(classification.score * modifier.modifier) : classification.score;
  }

  /**
   * Obtiene todos los headers críticos para un contexto
   */
  public getCriticalHeaders(context: string): HeaderClassification[] {
    return this.CLASSIFICATIONS.filter(h => {
      const modifier = h.contextModifiers.find(m => m.context === context);
      const adjustedScore = modifier ? h.score * modifier.modifier : h.score;
      return h.criticality === 'CRITICAL' && adjustedScore > 0;
    });
  }

  /**
   * Genera un reporte de headers recomendados para un contexto
   */
  public generateRecommendations(context: string): string {
    const critical = this.getCriticalHeaders(context);
    const high = this.CLASSIFICATIONS.filter(h => {
      const modifier = h.contextModifiers.find(m => m.context === context);
      const adjustedScore = modifier ? h.score * modifier.modifier : h.score;
      return h.criticality === 'HIGH' && adjustedScore > 0;
    });
    const medium = this.CLASSIFICATIONS.filter(h => {
      const modifier = h.contextModifiers.find(m => m.context === context);
      const adjustedScore = modifier ? h.score * modifier.modifier : h.score;
      return h.criticality === 'MEDIUM' && adjustedScore > 0;
    });

    let report = `# 🔒 Recomendaciones de Headers para Contexto: ${context}\n\n`;
    
    if (critical.length > 0) {
      report += `## 🚨 CRÍTICOS (Implementar inmediatamente)\n\n`;
      critical.forEach(header => {
        const adjustedScore = this.calculateAdjustedScore(header.name, context);
        report += `### ${header.name}\n`;
        report += `- **Score**: ${adjustedScore}pts\n`;
        report += `- **Descripción**: ${header.description}\n`;
        report += `- **Impacto**: ${header.impact}\n\n`;
      });
    }

    if (high.length > 0) {
      report += `## ⚠️ ALTOS (Implementar prioritariamente)\n\n`;
      high.forEach(header => {
        const adjustedScore = this.calculateAdjustedScore(header.name, context);
        report += `### ${header.name}\n`;
        report += `- **Score**: ${adjustedScore}pts\n`;
        report += `- **Descripción**: ${header.description}\n`;
        report += `- **Impacto**: ${header.impact}\n\n`;
      });
    }

    if (medium.length > 0) {
      report += `## ℹ️ MEDIOS (Implementar si es posible)\n\n`;
      medium.forEach(header => {
        const adjustedScore = this.calculateAdjustedScore(header.name, context);
        report += `### ${header.name}\n`;
        report += `- **Score**: ${adjustedScore}pts\n`;
        report += `- **Descripción**: ${header.description}\n`;
        report += `- **Impacto**: ${header.impact}\n\n`;
      });
    }

    report += `## 📊 Resumen\n\n`;
    report += `- **Headers críticos**: ${critical.length}\n`;
    report += `- **Headers altos**: ${high.length}\n`;
    report += `- **Headers medios**: ${medium.length}\n`;

    return report;
  }

  /**
   * Obtiene el score total máximo para un contexto
   */
  public getMaxScoreForContext(context: string): number {
    return this.CLASSIFICATIONS.reduce((total, header) => {
      const adjustedScore = this.calculateAdjustedScore(header.name, context);
      return total + adjustedScore;
    }, 0);
  }

  /**
   * Valida la configuración de un header
   */
  public validateHeader(headerName: string, value: string): { valid: boolean; issues: string[] } {
    const classification = this.getHeaderClassification(headerName);
    if (!classification) {
      return { valid: false, issues: ['Header no reconocido'] };
    }

    const issues: string[] = [];
    
    // Validaciones específicas por header
    switch (headerName) {
      case 'content-security-policy':
        if (!value.includes('default-src') && !value.includes('default-src')) {
          issues.push('CSP debería incluir default-src');
        }
        break;
      case 'strict-transport-security':
        if (!value.includes('max-age')) {
          issues.push('HSTS debe incluir max-age');
        }
        break;
      case 'x-frame-options':
        if (!value.includes('DENY') && !value.includes('SAMEORIGIN') && !value.includes('ALLOW-FROM')) {
          issues.push('X-Frame-Options debe ser DENY o SAMEORIGIN');
        }
        break;
    }

    return {
      valid: issues.length === 0,
      issues
    };
  }

  /**
   * Obtiene estadísticas de headers por criticidad
   */
  public getStatistics() {
    const stats = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      ACTIVE: 0,
      DEPRECATED: 0,
      OBSOLETE: 0
    };

    this.CLASSIFICATIONS.forEach(header => {
      stats[header.criticality]++;
      stats[header.legacyStatus]++;
    });

    return stats;
  }
}