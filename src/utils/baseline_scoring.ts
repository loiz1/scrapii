/**
 * Sistema de Baseline Scoring para Sitios Web Profesionales
 * Versión 3.0 - Professional Baseline Scoring
 * 
 * Sistema que establece scores base realistas para diferentes tipos de sitios web,
 * evitando penalizaciones excesivas y proporcionando benchmarks justos para
 * sitios como Alkosto y otros e-commerce profesionales.
 */

export interface BaselineConfig {
  type: SiteType;
  description: string;
  baseScore: number;
  expectedHeaders: ExpectedHeader[];
  typicalVulnerabilities: number;
  industry: IndustryType;
  riskProfile: RiskProfile;
  optimizationTargets: OptimizationTarget[];
}

export interface ExpectedHeader {
  name: string;
  expected: boolean;
  quality: 'basic' | 'good' | 'excellent';
  weight: number;
}

export interface OptimizationTarget {
  area: string;
  currentScore: number;
  targetScore: number;
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
}

export interface SiteAnalysis {
  siteType: SiteType;
  baselineScore: number;
  actualScore: number;
  gaps: ScoreGap[];
  industryComparison: IndustryBenchmark;
  recommendations: BaselineRecommendation[];
}

export interface ScoreGap {
  area: string;
  expected: number;
  actual: number;
  gap: number;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface IndustryBenchmark {
  averageScore: number;
  top10Percent: number;
  medianScore: number;
  percentile: number;
}

export interface BaselineRecommendation {
  category: string;
  action: string;
  expectedImpact: number;
  difficulty: 'easy' | 'medium' | 'hard';
  timeframe: string;
}

export type SiteType = 
  | 'ecommerce-standard' 
  | 'ecommerce-premium' 
  | 'enterprise-smb' 
  | 'enterprise-corporate' 
  | 'government' 
  | 'financial' 
  | 'healthcare' 
  | 'education' 
  | 'media-publisher' 
  | 'saas-platform'
  | 'portfolio-professional'
  | 'blog-influencer'
  | 'landing-page-conversion';

export type IndustryType = 
  | 'retail' 
  | 'finance' 
  | 'government' 
  | 'healthcare' 
  | 'education' 
  | 'technology' 
  | 'media' 
  | 'manufacturing' 
  | 'services' 
  | 'nonprofit';

export type RiskProfile = 'conservative' | 'moderate' | 'aggressive';

export class BaselineScorer {
  private readonly BASELINES: Record<SiteType, BaselineConfig> = {
    'ecommerce-standard': {
      type: 'ecommerce-standard',
      description: 'Tienda online estándar como Alkosto, MercadoLibre',
      baseScore: 75,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'good', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'good', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
        { name: 'referrer-policy', expected: false, quality: 'basic', weight: 8 },
      ],
      typicalVulnerabilities: 1, // E-commerce suelen tener ~1 vulnerabilidad menor
      industry: 'retail',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'CSP Implementation', currentScore: 60, targetScore: 85, effort: 'medium', impact: 'high' },
        { area: 'HTTPS Configuration', currentScore: 70, targetScore: 95, effort: 'low', impact: 'high' },
      ]
    },
    'ecommerce-premium': {
      type: 'ecommerce-premium',
      description: 'E-commerce premium como Amazon, tiendas de lujo',
      baseScore: 85,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'excellent', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'excellent', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'excellent', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'excellent', weight: 12 },
        { name: 'referrer-policy', expected: true, quality: 'excellent', weight: 8 },
      ],
      typicalVulnerabilities: 0,
      industry: 'retail',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'Advanced CSP', currentScore: 80, targetScore: 95, effort: 'high', impact: 'high' },
      ]
    },
    'enterprise-smb': {
      type: 'enterprise-smb',
      description: 'Sitios empresariales PYME',
      baseScore: 70,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'basic', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'basic', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
      ],
      typicalVulnerabilities: 2,
      industry: 'services',
      riskProfile: 'moderate',
      optimizationTargets: [
        { area: 'Basic Security Headers', currentScore: 50, targetScore: 75, effort: 'low', impact: 'high' },
      ]
    },
    'enterprise-corporate': {
      type: 'enterprise-corporate',
      description: 'Sitios corporativos grandes',
      baseScore: 80,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'good', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'excellent', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'good', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
        { name: 'referrer-policy', expected: true, quality: 'good', weight: 8 },
      ],
      typicalVulnerabilities: 1,
      industry: 'services',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'Corporate Security', currentScore: 70, targetScore: 90, effort: 'medium', impact: 'high' },
      ]
    },
    'portfolio-professional': {
      type: 'portfolio-professional',
      description: 'Portfolios y sitios personales profesionales',
      baseScore: 65,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'basic', weight: 20 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 15 },
        { name: 'x-frame-options', expected: false, quality: 'basic', weight: 8 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 10 },
      ],
      typicalVulnerabilities: 1,
      industry: 'services',
      riskProfile: 'moderate',
      optimizationTargets: [
        { area: 'Basic Protection', currentScore: 45, targetScore: 70, effort: 'low', impact: 'medium' },
      ]
    },
    'saas-platform': {
      type: 'saas-platform',
      description: 'Plataformas SaaS',
      baseScore: 78,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'good', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'good', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
        { name: 'referrer-policy', expected: true, quality: 'good', weight: 8 },
      ],
      typicalVulnerabilities: 1,
      industry: 'technology',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'SaaS Security', currentScore: 65, targetScore: 85, effort: 'medium', impact: 'high' },
      ]
    },
    'government': {
      type: 'government',
      description: 'Sitios gubernamentales',
      baseScore: 90,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'excellent', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'excellent', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'excellent', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'excellent', weight: 12 },
        { name: 'referrer-policy', expected: true, quality: 'excellent', weight: 8 },
      ],
      typicalVulnerabilities: 0,
      industry: 'government',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'Government Standards', currentScore: 85, targetScore: 95, effort: 'medium', impact: 'high' },
      ]
    },
    'financial': {
      type: 'financial',
      description: 'Instituciones financieras',
      baseScore: 95,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'excellent', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'excellent', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'excellent', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'excellent', weight: 12 },
        { name: 'referrer-policy', expected: true, quality: 'excellent', weight: 8 },
      ],
      typicalVulnerabilities: 0,
      industry: 'finance',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'Financial Grade Security', currentScore: 90, targetScore: 98, effort: 'high', impact: 'high' },
      ]
    },
    healthcare: {
      type: 'healthcare',
      description: 'Sitios de salud y medicina',
      baseScore: 85,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'excellent', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'excellent', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'good', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
      ],
      typicalVulnerabilities: 1,
      industry: 'healthcare',
      riskProfile: 'conservative',
      optimizationTargets: [
        { area: 'HIPAA Compliance', currentScore: 75, targetScore: 90, effort: 'medium', impact: 'high' },
      ]
    },
    education: {
      type: 'education',
      description: 'Sitios educativos y universidades',
      baseScore: 75,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'good', weight: 25 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 20 },
        { name: 'x-frame-options', expected: true, quality: 'good', weight: 15 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
      ],
      typicalVulnerabilities: 1,
      industry: 'education',
      riskProfile: 'moderate',
      optimizationTargets: [
        { area: 'Educational Security', currentScore: 65, targetScore: 80, effort: 'medium', impact: 'medium' },
      ]
    },
    'media-publisher': {
      type: 'media-publisher',
      description: 'Medios de comunicación y publishers',
      baseScore: 70,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'basic', weight: 20 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 15 },
        { name: 'x-frame-options', expected: false, quality: 'basic', weight: 10 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 12 },
      ],
      typicalVulnerabilities: 2,
      industry: 'media',
      riskProfile: 'moderate',
      optimizationTargets: [
        { area: 'Content Protection', currentScore: 55, targetScore: 75, effort: 'low', impact: 'medium' },
      ]
    },
    'blog-influencer': {
      type: 'blog-influencer',
      description: 'Blogs personales e influencers',
      baseScore: 60,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'basic', weight: 15 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 12 },
        { name: 'x-frame-options', expected: false, quality: 'basic', weight: 5 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 8 },
      ],
      typicalVulnerabilities: 1,
      industry: 'media',
      riskProfile: 'moderate',
      optimizationTargets: [
        { area: 'Basic Blog Security', currentScore: 45, targetScore: 65, effort: 'low', impact: 'low' },
      ]
    },
    'landing-page-conversion': {
      type: 'landing-page-conversion',
      description: 'Landing pages de conversión y marketing',
      baseScore: 65,
      expectedHeaders: [
        { name: 'content-security-policy', expected: true, quality: 'basic', weight: 18 },
        { name: 'strict-transport-security', expected: true, quality: 'good', weight: 15 },
        { name: 'x-frame-options', expected: true, quality: 'good', weight: 12 },
        { name: 'x-content-type-options', expected: true, quality: 'good', weight: 10 },
      ],
      typicalVulnerabilities: 1,
      industry: 'services',
      riskProfile: 'moderate',
      optimizationTargets: [
        { area: 'Landing Page Security', currentScore: 50, targetScore: 70, effort: 'low', impact: 'medium' },
      ]
    }
  };

  private readonly INDUSTRY_BENCHMARKS: Record<IndustryType, { average: number; top10Percent: number; median: number }> = {
    retail: { average: 72, top10Percent: 88, median: 70 },
    finance: { average: 85, top10Percent: 96, median: 83 },
    government: { average: 78, top10Percent: 92, median: 76 },
    healthcare: { average: 74, top10Percent: 89, median: 72 },
    education: { average: 68, top10Percent: 84, median: 66 },
    technology: { average: 76, top10Percent: 90, median: 74 },
    media: { average: 65, top10Percent: 82, median: 63 },
    manufacturing: { average: 69, top10Percent: 85, median: 67 },
    services: { average: 71, top10Percent: 87, median: 69 },
    nonprofit: { average: 62, top10Percent: 80, median: 60 }
  };

  /**
   * Obtiene la configuración de baseline para un tipo de sitio
   */
  public getBaselineForSite(siteType: SiteType): BaselineConfig {
    return this.BASELINES[siteType];
  }

  /**
   * Analiza un sitio contra su baseline esperado
   */
  public analyzeSite(
    siteType: SiteType,
    actualHeaders: Record<string, string>,
    actualVulnerabilities: { critical: number; high: number; medium: number; low: number }
  ): SiteAnalysis {
    
    const baseline = this.BASELINES[siteType];
    if (!baseline) {
      throw new Error(`Tipo de sitio no reconocido: ${siteType}`);
    }

    // Calcular score actual basado en headers presentes
    const headerScore = this.calculateHeaderScore(actualHeaders, baseline.expectedHeaders);
    
    // Calcular penalización por vulnerabilidades
    const vulnPenalty = this.calculateVulnerabilityPenalty(actualVulnerabilities, baseline.typicalVulnerabilities);
    
    // Score total
    const actualScore = Math.max(0, Math.min(100, baseline.baseScore + headerScore + vulnPenalty));
    
    // Identificar gaps
    const gaps = this.identifyGaps(actualHeaders, baseline.expectedHeaders);
    
    // Comparación con industria
    const industryBenchmark = this.getIndustryBenchmark(baseline.industry);
    
    // Generar recomendaciones
    const recommendations = this.generateRecommendations(gaps, baseline);
    
    return {
      siteType,
      baselineScore: baseline.baseScore,
      actualScore,
      gaps,
      industryComparison: industryBenchmark,
      recommendations
    };
  }

  /**
   * Calcula el score basado en headers presentes
   */
  private calculateHeaderScore(
    actualHeaders: Record<string, string>, 
    expectedHeaders: ExpectedHeader[]
  ): number {
    let score = 0;
    
    for (const expected of expectedHeaders) {
      const actualValue = actualHeaders[expected.name.toLowerCase()];
      
      if (actualValue) {
        // Header presente, calcular calidad
        const qualityMultiplier = this.getQualityMultiplier(expected.quality);
        score += expected.weight * qualityMultiplier;
      } else if (expected.expected) {
        // Header esperado pero no presente
        score -= expected.weight * 0.5; // Penalización parcial
      }
    }
    
    return score;
  }

  /**
   * Calcula penalización por vulnerabilidades
   */
  private calculateVulnerabilityPenalty(
    actualVulns: { critical: number; high: number; medium: number; low: number },
    typicalCount: number
  ): number {
    const totalVulns = actualVulns.critical + actualVulns.high + actualVulns.medium + actualVulns.low;
    const extraVulns = Math.max(0, totalVulns - typicalCount);
    
    if (extraVulns === 0) return 0;
    
    let penalty = 0;
    if (actualVulns.critical > 0) penalty -= 15 * actualVulns.critical;
    if (actualVulns.high > 0) penalty -= 8 * actualVulns.high;
    if (actualVulns.medium > 0) penalty -= 3 * actualVulns.medium;
    if (actualVulns.low > 0) penalty -= 1 * actualVulns.low;
    
    return Math.min(penalty, -20); // Límite máximo de penalización
  }

  /**
   * Identifica gaps entre esperado y actual
   */
  private identifyGaps(actualHeaders: Record<string, string>, expectedHeaders: ExpectedHeader[]): ScoreGap[] {
    const gaps: ScoreGap[] = [];
    
    for (const expected of expectedHeaders) {
      const actualValue = actualHeaders[expected.name.toLowerCase()];
      
      if (expected.expected && !actualValue) {
        gaps.push({
          area: expected.name,
          expected: expected.weight,
          actual: 0,
          gap: expected.weight,
          priority: expected.weight >= 20 ? 'critical' : expected.weight >= 15 ? 'high' : 'medium'
        });
      } else if (actualValue) {
        const actualQualityScore = this.calculateActualQualityScore(expected.name, actualValue);
        const expectedQualityScore = expected.weight * this.getQualityMultiplier(expected.quality);
        const gap = expectedQualityScore - actualQualityScore;
        
        if (gap > 5) { // Solo reportar gaps significativos
          gaps.push({
            area: expected.name,
            expected: expectedQualityScore,
            actual: actualQualityScore,
            gap,
            priority: gap >= 15 ? 'high' : 'medium'
          });
        }
      }
    }
    
    return gaps.sort((a, b) => b.gap - a.gap); // Ordenar por gap descendente
  }

  /**
   * Calcula el score de calidad actual de un header
   */
  private calculateActualQualityScore(headerName: string, value: string): number {
    switch (headerName.toLowerCase()) {
      case 'content-security-policy':
        return this.evaluateCSPQualityScore(value);
      case 'strict-transport-security':
        return this.evaluateHSTSQualityScore(value);
      case 'x-frame-options':
        return value.includes('DENY') || value.includes('SAMEORIGIN') ? 15 : 8;
      case 'x-content-type-options':
        return value.toLowerCase() === 'nosniff' ? 12 : 6;
      case 'referrer-policy':
        return 8; // Asumir calidad básica si está presente
      default:
        return 5; // Score básico para headers no reconocidos
    }
  }

  private evaluateCSPQualityScore(cspValue: string): number {
    let score = 10; // Base score
    
    if (cspValue.includes('default-src')) score += 5;
    if (cspValue.includes('script-src')) score += 5;
    if (cspValue.includes('style-src')) score += 3;
    if (!cspValue.includes("'unsafe-inline'")) score += 4;
    if (cspValue.includes('nonce-') || cspValue.includes('sha256-')) score += 3;
    
    return Math.min(25, score);
  }

  private evaluateHSTSQualityScore(hstsValue: string): number {
    let score = 10; // Base score
    
    if (hstsValue.includes('max-age=')) score += 5;
    if (hstsValue.includes('includeSubDomains')) score += 3;
    if (hstsValue.includes('preload')) score += 2;
    
    return Math.min(20, score);
  }

  /**
   * Obtiene benchmark de la industria
   */
  private getIndustryBenchmark(industry: IndustryType): IndustryBenchmark {
    const benchmark = this.INDUSTRY_BENCHMARKS[industry];
    
    return {
      averageScore: benchmark.average,
      top10Percent: benchmark.top10Percent,
      medianScore: benchmark.median,
      percentile: 50 // Se calculará dinámicamente
    };
  }

  /**
   * Genera recomendaciones basadas en gaps identificados
   */
  private generateRecommendations(gaps: ScoreGap[], baseline: BaselineConfig): BaselineRecommendation[] {
    const recommendations: BaselineRecommendation[] = [];
    
    // Ordenar gaps por prioridad
    const criticalGaps = gaps.filter(g => g.priority === 'critical');
    const highGaps = gaps.filter(g => g.priority === 'high');
    
    for (const gap of criticalGaps) {
      recommendations.push({
        category: 'Security Headers',
        action: `Implementar ${gap.area}`,
        expectedImpact: gap.gap,
        difficulty: 'easy',
        timeframe: '1-2 días'
      });
    }
    
    for (const gap of highGaps.slice(0, 3)) { // Máximo 3 recomendaciones de prioridad alta
      recommendations.push({
        category: 'Security Headers',
        action: `Mejorar ${gap.area}`,
        expectedImpact: gap.gap * 0.7,
        difficulty: 'medium',
        timeframe: '3-5 días'
      });
    }
    
    return recommendations;
  }

  /**
   * Obtiene multiplicador de calidad
   */
  private getQualityMultiplier(quality: 'basic' | 'good' | 'excellent'): number {
    switch (quality) {
      case 'basic': return 0.6;
      case 'good': return 0.8;
      case 'excellent': return 1.0;
    }
  }

  /**
   * Sugiere el tipo de sitio más apropiado para un URL o descripción
   */
  public suggestSiteType(url: string, description?: string): SiteType {
    const urlLower = url.toLowerCase();
    const descLower = (description || '').toLowerCase();
    
    // Heurísticas para determinar el tipo de sitio
    if (urlLower.includes('shop') || urlLower.includes('store') || urlLower.includes('cart')) {
      return 'ecommerce-standard';
    }
    
    if (descLower.includes('retail') || descLower.includes('tienda') || descLower.includes('ecommerce')) {
      return 'ecommerce-standard';
    }
    
    if (descLower.includes('corporate') || descLower.includes('empresa') || descLower.includes('business')) {
      return 'enterprise-smb';
    }
    
    if (descLower.includes('portfolio') || descLower.includes('personal') || descLower.includes('profesional')) {
      return 'portfolio-professional';
    }
    
    if (urlLower.includes('saas') || urlLower.includes('app') || descLower.includes('software')) {
      return 'saas-platform';
    }
    
    // Default para sitios未知
    return 'enterprise-smb';
  }
}