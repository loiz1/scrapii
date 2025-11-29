/**
 * Analizador Contextual de Riesgo para Headers de Seguridad
 * Versión 3.0 - Context-Aware Risk Assessment
 * 
 * Sistema que evalúa el contexto de un sitio web para determinar
 * si la ausencia de ciertos headers representa un riesgo real,
 * evitando penalizaciones innecesarias.
 */

export interface SiteContext {
  type: 'static' | 'dynamic' | 'ecommerce' | 'enterprise' | 'government' | 'api' | 'single-page-app' | 'blog' | 'portfolio';
  hasUserGeneratedContent: boolean;
  handlesFinancialData: boolean;
  hasLoginSystem: boolean;
  allowsFileUploads: boolean;
  usesExternalAPIs: boolean;
  hasThirdPartyIntegrations: boolean;
  isPublicFacing: boolean;
  usesHTTPS: boolean;
  technologyStack: string[];
  targetAudience: 'general' | 'business' | 'financial' | 'government' | 'enterprise' | 'developer';
}

export interface RiskAssessment {
  missingHeaders: MissingHeaderRisk[];
  overallRisk: RiskLevel;
  contextualScore: number;
  recommendations: string[];
}

export interface MissingHeaderRisk {
  headerName: string;
  originalCriticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  contextualCriticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  riskScore: number; // 0-100, cuanto contribuye al riesgo
  contextModifier: number; // Multiplicador del score original (0.1 = 10% del riesgo)
  reason: string;
  alternativeMitigations: string[];
}

export type RiskLevel = 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export class ContextualRiskAnalyzer {
  private readonly CONTEXT_MODIFIERS = {
    // Modificadores por tipo de sitio
    STATIC_SITE: {
      'content-security-policy': 0.3,  // Menos crítico en sitios estáticos
      'strict-transport-security': 1.0, // Sigue siendo crítico
      'x-frame-options': 0.8,          // Menos crítico si no hay interactividad
      'x-content-type-options': 0.9,   // Ligeramente menos crítico
      'referrer-policy': 0.5,          // Menos relevante
    },
    ECOMMERCE: {
      'content-security-policy': 1.2,  // Más crítico en e-commerce
      'strict-transport-security': 1.1, // Más crítico
      'x-frame-options': 1.0,          // Crítico para prevenir clickjacking
      'x-content-type-options': 1.0,   // Crítico
      'referrer-policy': 0.8,          // Importante para privacidad
    },
    API_ONLY: {
      'content-security-policy': 0.0,  // No aplica para APIs
      'strict-transport-security': 0.9, // Sigue siendo importante
      'x-frame-options': 0.0,          // No aplica para APIs
      'x-content-type-options': 0.7,   // Menos crítico para APIs
      'referrer-policy': 0.2,          // Poco relevante para APIs
    },
    SINGLE_PAGE_APP: {
      'content-security-policy': 0.9,  // Crítico pero puede ser más flexible
      'strict-transport-security': 1.0, // Sigue siendo crítico
      'x-frame-options': 0.9,          // Importante
      'x-content-type-options': 0.9,   // Importante
      'referrer-policy': 0.7,          // Moderadamente importante
    },
    BLOG_PORTFOLIO: {
      'content-security-policy': 0.4,  // Menos crítico para contenido estático
      'strict-transport-security': 0.8, // Menos crítico pero recomendado
      'x-frame-options': 0.3,          // Poco crítico para sitios públicos
      'x-content-type-options': 0.6,   // Moderadamente importante
      'referrer-policy': 1.1,          // Más importante para privacidad
    }
  };

  /**
   * Analiza el riesgo contextual de headers faltantes
   */
  public analyzeContextualRisk(
    missingHeaders: string[],
    context: SiteContext
  ): RiskAssessment {
    
    const missingHeaderRisks: MissingHeaderRisk[] = [];
    const baseCriticality = this.getContextBaseCriticality(context.type);
    
    for (const headerName of missingHeaders) {
      const risk = this.analyzeSingleHeaderRisk(headerName, context, baseCriticality);
      if (risk) {
        missingHeaderRisks.push(risk);
      }
    }
    
    // Calcular score contextual general
    const contextualScore = this.calculateContextualScore(missingHeaderRisks, context);
    
    // Determinar nivel de riesgo general
    const overallRisk = this.determineOverallRisk(contextualScore, missingHeaderRisks);
    
    // Generar recomendaciones
    const recommendations = this.generateRecommendations(missingHeaderRisks, context);
    
    return {
      missingHeaders: missingHeaderRisks,
      overallRisk,
      contextualScore,
      recommendations
    };
  }

  /**
   * Analiza el riesgo de un header específico en un contexto
   */
  private analyzeSingleHeaderRisk(
    headerName: string,
    context: SiteContext,
    baseCriticality: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>
  ): MissingHeaderRisk | null {
    
    const originalCriticality = baseCriticality[headerName] || 'MEDIUM';
    const contextModifiers = this.getContextModifiersForType(context.type);
    const modifier = contextModifiers[headerName] || 1.0;
    
    // No analizar si el header no aplica en este contexto
    if (modifier === 0.0) {
      return null;
    }
    
    const contextualCriticality = this.adjustCriticality(originalCriticality, modifier);
    const riskScore = this.calculateRiskScore(originalCriticality, modifier, context);
    const reason = this.generateRiskReason(headerName, context, modifier);
    const alternativeMitigations = this.getAlternativeMitigations(headerName, context);
    
    return {
      headerName,
      originalCriticality,
      contextualCriticality,
      riskScore,
      contextModifier: modifier,
      reason,
      alternativeMitigations
    };
  }

  /**
   * Obtiene la criticidad base según el tipo de sitio
   */
  private getContextBaseCriticality(siteType: SiteContext['type']): Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> {
    const baseCriticality: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> = {
      'content-security-policy': 'CRITICAL',
      'strict-transport-security': 'CRITICAL',
      'x-frame-options': 'HIGH',
      'x-content-type-options': 'HIGH',
      'referrer-policy': 'MEDIUM',
      'permissions-policy': 'MEDIUM',
      'x-xss-protection': 'LOW'
    };
    
    // Ajustes específicos por tipo de sitio
    switch (siteType) {
      case 'static':
      case 'blog':
      case 'portfolio':
        baseCriticality['content-security-policy'] = 'HIGH'; // Menos crítico
        baseCriticality['referrer-policy'] = 'HIGH'; // Más importante para privacidad
        break;
        
      case 'ecommerce':
        baseCriticality['content-security-policy'] = 'CRITICAL'; // Más crítico
        baseCriticality['x-frame-options'] = 'CRITICAL'; // Previene clickjacking en pagos
        break;
        
      case 'api':
        baseCriticality['content-security-policy'] = 'LOW'; // No aplica
        baseCriticality['x-frame-options'] = 'LOW'; // No aplica
        break;
        
      case 'government':
      case 'enterprise':
        baseCriticality['permissions-policy'] = 'HIGH'; // Control granular importante
        break;
    }
    
    return baseCriticality;
  }

  /**
   * Obtiene modificadores contextuales para un tipo de sitio
   */
  private getContextModifiersForType(siteType: SiteContext['type']): Record<string, number> {
    const modifiers = this.CONTEXT_MODIFIERS.STATIC_SITE; // Base
    
    switch (siteType) {
      case 'static':
      case 'blog':
      case 'portfolio':
        return { ...modifiers, ...this.CONTEXT_MODIFIERS.BLOG_PORTFOLIO };
        
      case 'ecommerce':
        return { ...modifiers, ...this.CONTEXT_MODIFIERS.ECOMMERCE };
        
      case 'api':
        return { ...modifiers, ...this.CONTEXT_MODIFIERS.API_ONLY };
        
      case 'single-page-app':
        return { ...modifiers, ...this.CONTEXT_MODIFIERS.SINGLE_PAGE_APP };
        
      default:
        return modifiers;
    }
  }

  /**
   * Ajusta la criticidad basándose en el modificador contextual
   */
  private adjustCriticality(originalCriticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW', modifier: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    if (modifier >= 1.2) {
      // Aumentar criticidad
      switch (originalCriticality) {
        case 'LOW': return 'MEDIUM';
        case 'MEDIUM': return 'HIGH';
        case 'HIGH': return 'CRITICAL';
        case 'CRITICAL': return 'CRITICAL';
      }
    } else if (modifier <= 0.3) {
      // Reducir criticidad
      switch (originalCriticality) {
        case 'CRITICAL': return 'HIGH';
        case 'HIGH': return 'MEDIUM';
        case 'MEDIUM': return 'LOW';
        case 'LOW': return 'LOW';
      }
    }
    
    return originalCriticality;
  }

  /**
   * Calcula el score de riesgo ajustado contextualmente
   */
  private calculateRiskScore(
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    modifier: number,
    context: SiteContext
  ): number {
    const baseScores = { CRITICAL: 100, HIGH: 70, MEDIUM: 40, LOW: 15 };
    let score = baseScores[criticality] * modifier;
    
    // Ajustes adicionales por factores contextuales
    if (context.hasUserGeneratedContent) score *= 1.3;
    if (context.handlesFinancialData) score *= 1.5;
    if (context.hasLoginSystem) score *= 1.2;
    if (context.isPublicFacing) score *= 0.9;
    
    return Math.round(score);
  }

  /**
   * Genera la explicación del riesgo contextual
   */
  private generateRiskReason(headerName: string, context: SiteContext, modifier: number): string {
    const reasons = {
      'content-security-policy': this.getCSPReason(context, modifier),
      'strict-transport-security': this.getHSTSReason(context, modifier),
      'x-frame-options': this.getXFOReason(context, modifier),
      'x-content-type-options': this.getXCTOReason(context, modifier),
      'referrer-policy': this.getReferrerReason(context, modifier),
    };
    
    return reasons[headerName as keyof typeof reasons] || `Header ${headerName} tiene riesgo ${modifier > 1 ? 'incrementado' : 'reducido'} en este contexto.`;
  }

  private getCSPReason(context: SiteContext, modifier: number): string {
    if (modifier === 0.0) return 'CSP no es relevante para APIs o servicios sin interfaz web.';
    if (modifier < 0.5) return 'CSP es menos crítico en sitios estáticos con poco JavaScript dinámico.';
    if (modifier > 1.1) return 'CSP es especialmente crítico debido al contenido dinámico y/o e-commerce.';
    return 'CSP es importante para prevenir ataques XSS en contenido dinámico.';
  }

  private getHSTSReason(context: SiteContext, modifier: number): string {
    if (!context.usesHTTPS) return 'HSTS requiere HTTPS para ser efectivo.';
    if (modifier < 0.9) return 'HSTS es menos crítico para APIs que para sitios web públicos.';
    return 'HSTS es crítico para prevenir ataques de downgrade y MITM.';
  }

  private getXFOReason(context: SiteContext, modifier: number): string {
    if (modifier === 0.0) return 'X-Frame-Options no es relevante para APIs.';
    if (modifier < 0.5) return 'Clickjacking es menos probable en sitios estáticos.';
    return 'X-Frame-Options previene clickjacking, especialmente importante para formularios de pago.';
  }

  private getXCTOReason(context: SiteContext, modifier: number): string {
    if (modifier < 0.8) return 'MIME sniffing es menos crítico para APIs.';
    return 'X-Content-Type-Options previene ataques de MIME sniffing.';
  }

  private getReferrerReason(context: SiteContext, modifier: number): string {
    if (modifier > 1.0) return 'Control de referrer es especialmente importante para privacidad.';
    if (modifier < 0.5) return 'Referrer policy es menos crítica para sitios estáticos.';
    return 'Referrer policy controla la exposición de información de navegación.';
  }

  /**
   * Obtiene mitigaciones alternativas para headers faltantes
   */
  private getAlternativeMitigations(headerName: string, context: SiteContext): string[] {
    const alternatives: Record<string, string[]> = {
      'content-security-policy': [
        'Usar frameworks que incluyen CSP automático (React, Vue)',
        'Implementar sanitización de entrada riguroso',
        'Usar bibliotecas de escape de HTML (DOMPurify)',
        'Configurar CSP mínimo en servidor web'
      ],
      'strict-transport-security': [
        'Configurar HSTS en el servidor web/load balancer',
        'Usar certificados SSL con pinning',
        'Monitorear certificados automáticamente'
      ],
      'x-frame-options': [
        'Configurar frame-ancestors en CSP',
        'Verificar origen de requests en backend',
        'Implementar tokens anti-CSRF'
      ],
      'x-content-type-options': [
        'Configurar tipo MIME correcto en servidor',
        'Usar bibliotecas que establecen Content-Type apropiadamente',
        'Validar tipos de archivo antes de procesar'
      ]
    };
    
    return alternatives[headerName] || ['Configurar este header en el servidor web'];
  }

  /**
   * Calcula el score contextual general
   */
  private calculateContextualScore(missingHeaderRisks: MissingHeaderRisk[], context: SiteContext): number {
    if (missingHeaderRisks.length === 0) return 100;
    
    const totalRisk = missingHeaderRisks.reduce((sum, risk) => sum + risk.riskScore, 0);
    const baseScore = Math.max(0, 100 - totalRisk);
    
    // Bonificaciones por buenas prácticas contextuales
    let bonus = 0;
    if (context.usesHTTPS) bonus += 5;
    if (context.hasUserGeneratedContent && context.usesExternalAPIs) bonus += 3;
    if (context.type === 'blog' || context.type === 'portfolio') bonus += 5; // Sitios simples
        
    return Math.min(100, baseScore + bonus);
  }

  /**
   * Determina el nivel de riesgo general
   */
  private determineOverallRisk(score: number, missingHeaderRisks: MissingHeaderRisk[]): RiskLevel {
    const criticalCount = missingHeaderRisks.filter(r => r.contextualCriticality === 'CRITICAL').length;
    const highCount = missingHeaderRisks.filter(r => r.contextualCriticality === 'HIGH').length;
    
    if (criticalCount > 0 || score < 30) return 'CRITICAL';
    if (highCount > 0 || score < 50) return 'HIGH';
    if (score < 70) return 'MEDIUM';
    if (score < 85) return 'LOW';
    return 'MINIMAL';
  }

  /**
   * Genera recomendaciones específicas del contexto
   */
  private generateRecommendations(missingHeaderRisks: MissingHeaderRisk[], context: SiteContext): string[] {
    const recommendations: string[] = [];
    
    // Priorizar headers críticos contextuales
    const criticalHeaders = missingHeaderRisks.filter(r => r.contextualCriticality === 'CRITICAL');
    if (criticalHeaders.length > 0) {
      recommendations.push(`🚨 PRIORIDAD ALTA: Implementar ${criticalHeaders.map(h => h.headerName).join(', ')}`);
    }
    
    // Recomendaciones específicas por tipo de sitio
    switch (context.type) {
      case 'ecommerce':
        recommendations.push('💳 Para e-commerce: Implementar CSP estricto con nonces para prevenir XSS en pagos');
        recommendations.push('🔒 Configurar HSTS con preload para máxima seguridad HTTPS');
        break;
        
      case 'api':
        recommendations.push('🔧 Para APIs: Focus en HSTS y X-Content-Type-Options');
        recommendations.push('📡 Considerar rate limiting y autenticación robusta como alternativa a CSP');
        break;
        
      case 'static':
      case 'blog':
      case 'portfolio':
        recommendations.push('📄 Para sitios estáticos: CSP básico es suficiente, priorizar HTTPS');
        recommendations.push('🎨 Considerar CSP con "self" y dominios CDN específicos');
        break;
    }
    
    // Recomendaciones por tecnología
    if (context.technologyStack.includes('react')) {
      recommendations.push('⚛️ React: Usar dangerouslySetInnerHTML con precaución o usar bibliotecas como DOMPurify');
    }
    
    if (context.technologyStack.includes('vue')) {
      recommendations.push('💚 Vue: Usar v-html con filtros de sanitización');
    }
    
    return recommendations;
  }
}