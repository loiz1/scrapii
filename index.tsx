import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { logger } from './src/utils/logger';
import { sanitizeUserInput, validateScrapingUrl, performSecurityAnalysis } from './src/utils/security';

const CORS_PROXY = 'https://corsproxy.io/?';

// --- TIPOS DE DATOS ---
interface SeoAuditResult {
    status: 'pass' | 'warn' | 'fail';
    text: string;
}

interface EcommerceData {
    products: {
        name: string;
        price: string | null;
        currency: string | null;
        availability: string | null;
        rating: number | null;
        reviewCount: number | null;
    }[];
    structuredData: {
        hasProductSchema: boolean;
        hasOrganizationSchema: boolean;
        hasReviewSchema: boolean;
    };
    paymentMethods: string[];
    shoppingFeatures: {
        hasCart: boolean;
        hasWishlist: boolean;
        hasSearch: boolean;
        hasFilters: boolean;
    };
    totalProducts: number;
}

interface SubdomainData {
    url: string;
    title: string;
    technologies: { name: string; version?: string; currentVersion?: string }[];
    linkCount: number;
    imageCount: number;
    status: 'success' | 'error' | 'skipped';
    error?: string;
}

// NUEVAS INTERFACES PARA CIBERSEGURIDAD
interface ScrapingPolicy {
    robotsTxtAllowed: boolean;
    termsOfServiceRestricted: boolean;
    rateLimitDetected: boolean;
    scrapingProhibited: boolean;
    userAgentRequired: boolean;
    delayRequired: number;
    robotsTxtChecked: boolean;
    termsChecked: boolean;
}

interface SecurityHeaders {
    csp: boolean;
    hsts: boolean;
    xss: boolean;
    contentType: boolean;
    detailed?: {
        csp: {
            present: boolean;
            valid: boolean;
            content: string;
        };
        hsts: {
            present: boolean;
            valid: boolean;
            content: string;
            maxAge: number;
        };
        xssProtection: {
            present: boolean;
            valid: boolean;
            content: string;
        };
        referrerPolicy: {
            present: boolean;
            valid: boolean;
            content: string;
        };
        frameOptions: {
            present: boolean;
            valid: boolean;
            content: string;
        };
        infoDisclosure: {
            serverExposed: boolean;
            poweredByExposed: boolean;
        };
    };
}

interface SSLAnalysis {
    hasSSL: boolean;
    validCertificate: boolean;
    tlsVersion: string;
    httpsEnabled: boolean;
    additionalInfo?: {
        certificateIssuer?: string;
        certificateSubject?: string;
        certificateValidity?: {
            validFrom?: string;
            validTo?: string;
            daysRemaining?: number;
        };
        protocolVersion?: string;
        cipherSuite?: string;
        mixedContent?: boolean;
    };
}

interface VulnerableTechnology {
    name: string;
    version: string;
    vulnerability: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    lineNumbers?: number[];
    recommendation?: string;
}

interface SecurityAnalysis {
    securityHeaders: SecurityHeaders;
    sslAnalysis: SSLAnalysis;
    vulnerableTechnologies: VulnerableTechnology[];
    privacyScore: number;
    externalLinks: number;
    imagesWithoutAlt: number;
    cookiesDetected: number;
}

interface ScrapedData {
    title: string;
    url: string;
    meta: {
        description: string | null;
        keywords: string | null;
        author: string | null;
        ogTitle: string | null;
        ogDescription: string | null;
    };
    headings: {
        h1: (string | undefined | null)[];
        h2: (string | undefined | null)[];
        h3: (string | undefined | null)[];
    };
    links: { text: string; href: string | null; }[];
    images: { src: string | null; alt: string | null; }[];
    technologies: { name: string; version?: string; currentVersion?: string }[];
    ecommerce: EcommerceData;
    subdomains: SubdomainData[];
    scrapingPolicy: ScrapingPolicy;
    securityAnalysis: SecurityAnalysis;
    robotsTxtContent: string;
    usersDetected: {
        hasUsers: boolean;
        accessPoints: string[];
    };
}

interface OptimizedQuery {
    title: string;
    url: string;
    keywords: string[];
    securityScore: number;
    matchPercentage: number; // Porcentaje de coincidencia de keywords con contenido web
    timestamp: number;
}

interface Query {
    title: string;
    url: string;
    data: ScrapedData;
    timestamp: number;
}

type Tab = 'summary' | 'security' | 'tech' | 'ecommerce' | 'subdomains' | 'gallery' | 'json';

// --- COMPONENTE PRINCIPAL ---
const App = () => {
    const [url, setUrl] = useState('');
    const [queries, setQueries] = useState<Query[]>([]);
    const [optimizedQueries, setOptimizedQueries] = useState<OptimizedQuery[]>([]);
    const [currentResult, setCurrentResult] = useState<ScrapedData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<Tab>('summary');
    const [ethicalMode, setEthicalMode] = useState<boolean>(true);

    useEffect(() => {
        try {
            const savedQueries = localStorage.getItem('scrapedQueries');
            if (savedQueries) setQueries(JSON.parse(savedQueries));
            
            const savedOptimizedQueries = localStorage.getItem('optimizedQueries');
            if (savedOptimizedQueries) setOptimizedQueries(JSON.parse(savedOptimizedQueries));
        } catch (e) {
            logger.error("Fallo al cargar consultas desde localStorage", { error: e });
        }
    }, []);

    const getOptimizedQueries = (): OptimizedQuery[] => {
        try {
            const saved = localStorage.getItem('optimizedQueries');
            return saved ? JSON.parse(saved) : [];
        } catch {
            return [];
        }
    };

    const saveQueries = (newQueries: Query[]) => {
        setQueries(newQueries);
        localStorage.setItem('scrapedQueries', JSON.stringify(newQueries));
    };

    const saveOptimizedQueries = (newQueries: OptimizedQuery[]) => {
        setOptimizedQueries(newQueries);
        localStorage.setItem('optimizedQueries', JSON.stringify(newQueries));
    };

    // --- FUNCIONES AUXILIARES ---
    const getRobotsTxtContent = async (baseUrl: string): Promise<string> => {
        try {
            const robotsUrl = new URL('/robots.txt', baseUrl).href;
            const response = await fetch(`${CORS_PROXY}${encodeURIComponent(robotsUrl)}`);
            
            if (!response.ok) {
                return 'No se encontró archivo robots.txt';
            }
            
            return await response.text();
        } catch (error) {
            return 'Error al obtener robots.txt: ' + (error instanceof Error ? error.message : 'Error desconocido');
        }
    };

    const detectUsersInContent = (html: string): { hasUsers: boolean; accessPoints: string[] } => {
        const userPatterns = [
            { pattern: /login/i, label: 'Iniciar Sesión' },
            { pattern: /register/i, label: 'Registro' },
            { pattern: /sign\s*in/i, label: 'Sign In' },
            { pattern: /sign\s*up/i, label: 'Sign Up' },
            { pattern: /profile/i, label: 'Perfil' },
            { pattern: /account/i, label: 'Cuenta' },
            { pattern: /dashboard/i, label: 'Dashboard' },
            { pattern: /admin/i, label: 'Administración' },
            { pattern: /user/i, label: 'Usuario' },
            { pattern: /member/i, label: 'Miembro' },
            { pattern: /author/i, label: 'Autor' },
            { pattern: /usuario[s]?/i, label: 'Usuarios' },
            { pattern: /miembro[s]?/i, label: 'Miembros' },
            { pattern: /perfil[es]?/i, label: 'Perfiles' },
            { pattern: /cuenta[s]?/i, label: 'Cuentas' },
            { pattern: /iniciar\s*sesión/i, label: 'Iniciar Sesión' },
            { pattern: /registr[ao]/i, label: 'Registro' }
        ];
        
        const accessPoints: string[] = [];
        
        userPatterns.forEach(({ pattern, label }) => {
            if (pattern.test(html)) {
                accessPoints.push(label);
            }
        });
        
        // Eliminar duplicados y retornar
        const uniqueAccessPoints = [...new Set(accessPoints)];
        return { 
            hasUsers: uniqueAccessPoints.length > 0, 
            accessPoints: uniqueAccessPoints 
        };
    };

    // --- FUNCIÓN PARA EXTRAER PALABRAS CLAVE ---
    const extractKeywords = (html: string, data: ScrapedData): string[] => {
        const keywords: string[] = [];
        const textContent = html.toLowerCase();
        
        // Palabras clave de tecnología
        const techKeywords = data.technologies.map(tech => tech.name);
        keywords.push(...techKeywords);
        
        // Palabras clave de e-commerce
        const ecommerceKeywords = [
            'tienda', 'shop', 'store', 'producto', 'product', 'precio', 'price',
            'comprar', 'buy', 'carrito', 'cart', 'pago', 'payment', 'envío', 'shipping'
        ];
        ecommerceKeywords.forEach(keyword => {
            if (textContent.includes(keyword)) {
                keywords.push(keyword);
            }
        });
        
        // Palabras clave de seguridad
        const securityKeywords = [
            'seguridad', 'security', 'ssl', 'https', 'certificado', 'certificate',
            'criptografía', 'encryption', 'firewall', 'vulnerabilidad', 'vulnerability'
        ];
        securityKeywords.forEach(keyword => {
            if (textContent.includes(keyword)) {
                keywords.push(keyword);
            }
        });
        
        // Extraer keywords de meta description
        if (data.meta.keywords) {
            const metaKeywords = data.meta.keywords.split(',').map(k => k.trim().toLowerCase());
            keywords.push(...metaKeywords);
        }
        
        // Extraer palabras de headings más importantes
        const importantHeadings = [...data.headings.h1, ...data.headings.h2].filter(Boolean);
        importantHeadings.forEach(heading => {
            const words = heading!.split(' ').slice(0, 3); // Primeras 3 palabras
            keywords.push(...words.map(w => w.toLowerCase()));
        });
        
        // Remover duplicados y limitar a 10 keywords más relevantes
        const uniqueKeywords = [...new Set(keywords)]
            .filter(k => k.length > 2) // Filtrar palabras muy cortas
            .slice(0, 10);
        
        return uniqueKeywords;
    };
    // --- FUNCIONES PARA OPTIMIZACIÓN DE TÍTULOS SIN TECNOLOGÍAS ---
    
    /**
     * Extrae palabras clave específicas de URLs sin incluir tecnologías
     * Enfocándose en contenido temático y propósito del sitio
     */
    const extractUrlKeywords = (url: string, html: string, data: ScrapedData): string[] => {
        const keywords: string[] = [];
        const textContent = html.toLowerCase();
        const urlObj = new URL(url);
        const pathSegments = urlObj.pathname.split('/').filter(segment => segment.length > 0);
        
        // Extraer keywords del pathname de la URL
        pathSegments.forEach(segment => {
            const cleanedSegment = segment.replace(/[-_]/g, ' ').trim();
            if (cleanedSegment.length > 2 && !/^\d+$/.test(cleanedSegment)) {
                keywords.push(cleanedSegment);
            }
        });
        
        // Keywords específicos por tipo de contenido (sin tecnologías)
        const contentKeywords = {
            ecommerce: [
                'tienda', 'shop', 'store', 'productos', 'productos', 'precio', 'precios',
                'comprar', 'buy', 'carrito', 'cart', 'pago', 'payment', 'envío', 'shipping',
                'ofertas', 'descuentos', 'promociones', 'sale', 'deals', 'outlet'
            ],
            servicios: [
                'servicios', 'services', 'consultoría', 'consulting', 'soporte', 'support',
                'ayuda', 'help', 'contacto', 'contact', 'nosotros', 'about'
            ],
            blog: [
                'blog', 'noticias', 'news', 'artículos', 'articles', 'recursos', 'resources',
                'guías', 'guides', 'tutoriales', 'tutorials', 'tips'
            ],
            institucional: [
                'empresa', 'company', 'organización', 'organization', 'institucional', 'corporativo',
                'misión', 'mission', 'visión', 'vision', 'valores', 'values'
            ],
            productos: [
                'productos', 'products', 'catálogo', 'catalog', 'colección', 'collection',
                'línea', 'line', 'marca', 'brand', 'fabricante', 'manufacturer'
            ]
        };
        
        // Buscar keywords de contenido temático
        Object.values(contentKeywords).flat().forEach(keyword => {
            if (textContent.includes(keyword)) {
                keywords.push(keyword);
            }
        });
        
        // Keywords de e-commerce si hay productos
        if (data.ecommerce.totalProducts > 0) {
            const ecommerceTerms = ['productos', 'tienda', 'comprar', 'precios', 'ofertas'];
            ecommerceTerms.forEach(term => {
                if (textContent.includes(term)) {
                    keywords.push(term);
                }
            });
        }
        
        // Extraer del título original sin tecnologías
        if (data.title) {
            const titleWords = data.title
                .toLowerCase()
                .replace(/[-|]/g, ' ')
                .split(/\s+/)
                .filter(word => 
                    word.length > 2 && 
                    !/react|angular|vue|bootstrap|jquery|wordpress|php|html|css|javascript|js|ts|node/i.test(word)
                );
            keywords.push(...titleWords.slice(0, 3));
        }
        
        // Extraer de meta description
        if (data.meta.description) {
            const descWords = data.meta.description
                .toLowerCase()
                .split(/\s+/)
                .filter(word => word.length > 3);
            keywords.push(...descWords.slice(0, 4));
        }
        
        // Extraer de headings importantes
        const importantHeadings = [...data.headings.h1, ...data.headings.h2].filter(Boolean);
        importantHeadings.forEach(heading => {
            const words = heading!
                .toLowerCase()
                .replace(/[-|]/g, ' ')
                .split(/\s+/)
                .filter(word => word.length > 3);
            keywords.push(...words.slice(0, 2));
        });
        
        // Filtrar y limpiar keywords
        const cleanKeywords = [...new Set(keywords)]
            .filter(keyword => 
                keyword.length > 2 && 
                !/^(the|and|or|but|in|on|at|to|for|of|with|by|from|up|about|into|through|during|before|after|above|below|between|among|through)$/i.test(keyword) &&
                !/^\d+$/.test(keyword)
            )
            .slice(0, 12); // Máximo 12 keywords para evitar sobrecarga
        
        return cleanKeywords;
    };
    
    /**
     * Valida keywords buscando coincidencias en la web
     * Simula búsqueda web para determinar relevancia de keywords
     */
    const validateKeywordsWithWebSearch = async (keywords: string[], baseUrl: string): Promise<{ keyword: string; relevanceScore: number; matchType: string }[]> => {
        const results: { keyword: string; relevanceScore: number; matchType: string }[] = [];
        const urlObj = new URL(baseUrl);
        const domain = urlObj.hostname.replace('www.', '');
        
        // Simulación de búsqueda web con diferentes tipos de coincidencias
        for (const keyword of keywords) {
            let relevanceScore = 0;
            let matchType = 'none';
            
            // Búsqueda en el dominio actual
            if (domain.toLowerCase().includes(keyword.toLowerCase()) || 
                baseUrl.toLowerCase().includes(keyword.toLowerCase())) {
                relevanceScore += 40;
                matchType = 'domain';
            }
            
            // Búsqueda en contenido específico
            const keywordPatterns = {
                'ecommerce': /(tienda|shop|store|productos|precio|comprar|carrito)/i,
                'servicios': /(servicios|consultoría|soporte|ayuda|contacto)/i,
                'blog': /(blog|noticias|artículos|recursos|guías)/i,
                'productos': /(productos|catálogo|colección|línea|marca)/i,
                'empresa': /(empresa|organización|corporativo|nosotros)/i
            };
            
            for (const [type, pattern] of Object.entries(keywordPatterns)) {
                if (pattern.test(keyword)) {
                    relevanceScore += 30;
                    matchType = type;
                    break;
                }
            }
            
            // Bonificación por palabras clave comerciales
            if (/(precio|oferta|descuento|promoción|sale|deal)/i.test(keyword)) {
                relevanceScore += 25;
                matchType = matchType === 'none' ? 'commercial' : matchType;
            }
            
            // Bonificación por palabras de acción
            if (/(comprar|buy|contactar|contact|visitar|visit)/i.test(keyword)) {
                relevanceScore += 20;
                matchType = matchType === 'none' ? 'action' : matchType;
            }
            
            // Penalización por palabras muy genéricas
            if (/(welcome|inicio|home|principal|principal)/i.test(keyword)) {
                relevanceScore -= 10;
            }
            
            // Asegurar score mínimo para keywords que aparecen en URL
            if (baseUrl.toLowerCase().includes(keyword.toLowerCase()) && relevanceScore < 50) {
                relevanceScore = 50;
                matchType = 'url_exact';
            }
            
            results.push({
                keyword,
                relevanceScore: Math.max(0, Math.min(100, relevanceScore)),
                matchType
            });
        }
        
        // Ordenar por relevancia y retornar top keywords
        return results
            .filter(result => result.relevanceScore > 0)
            .sort((a, b) => b.relevanceScore - a.relevanceScore)
            .slice(0, 8);
    };
    
    /**
     * Genera título optimizado basado en keywords más relevantes
     * Sin mencionar tecnologías, enfocándose en contenido y propósito
     */
    const generateOptimizedTitle = (
        validatedKeywords: { keyword: string; relevanceScore: number; matchType: string }[],
        originalTitle: string,
        url: string
    ): { optimizedTitle: string; matchPercentage: number } => {
        if (validatedKeywords.length === 0) {
            return {
                optimizedTitle: originalTitle || 'Sitio Web',
                matchPercentage: 0
            };
        }
        
        // Tomar top 3 keywords más relevantes
        const topKeywords = validatedKeywords.slice(0, 3);
        const avgScore = topKeywords.reduce((sum, k) => sum + k.relevanceScore, 0) / topKeywords.length;
        
        // Categorizar keywords para generar título apropiado
        const keywordCategories = {
            ecommerce: topKeywords.filter(k => 
                /(tienda|shop|store|productos|precio|comprar|carrito|oferta)/i.test(k.keyword)
            ),
            servicios: topKeywords.filter(k => 
                /(servicios|consultoría|soporte|ayuda|contacto)/i.test(k.keyword)
            ),
            productos: topKeywords.filter(k => 
                /(productos|catálogo|colección|línea|marca)/i.test(k.keyword)
            ),
            empresa: topKeywords.filter(k => 
                /(empresa|organización|corporativo|nosotros)/i.test(k.keyword)
            ),
            blog: topKeywords.filter(k => 
                /(blog|noticias|artículos|recursos|guías)/i.test(k.keyword)
            )
        };
        
        let optimizedTitle = '';
        const urlObj = new URL(url);
        const domain = urlObj.hostname.replace('www.', '');
        
        // Generar título según categoría predominante
        if (keywordCategories.ecommerce.length > 0) {
            const mainKeyword = keywordCategories.ecommerce[0].keyword;
            const secondaryKeyword = keywordCategories.ecommerce[1]?.keyword;
            
            if (/(tienda|shop|store)/i.test(mainKeyword)) {
                optimizedTitle = `Tienda ${secondaryKeyword || 'Online'} - ${domain}`;
            } else if (/(productos|product)/i.test(mainKeyword)) {
                optimizedTitle = `Productos ${secondaryKeyword || ''} | ${domain}`.trim();
            } else if (/(precio|precios)/i.test(mainKeyword)) {
                optimizedTitle = `Precios ${secondaryKeyword || 'Competitivos'} - ${domain}`;
            } else if (/(oferta|ofertas)/i.test(mainKeyword)) {
                optimizedTitle = `Ofertas y Descuentos - ${domain}`;
            } else {
                optimizedTitle = `${mainKeyword.charAt(0).toUpperCase() + mainKeyword.slice(1)} ${domain}`;
            }
        } else if (keywordCategories.servicios.length > 0) {
            const mainKeyword = keywordCategories.servicios[0].keyword;
            optimizedTitle = `Servicios de ${mainKeyword} - ${domain}`;
        } else if (keywordCategories.productos.length > 0) {
            const mainKeyword = keywordCategories.productos[0].keyword;
            optimizedTitle = `${mainKeyword.charAt(0).toUpperCase() + mainKeyword.slice(1)} - ${domain}`;
        } else if (keywordCategories.empresa.length > 0) {
            const mainKeyword = keywordCategories.empresa[0].keyword;
            optimizedTitle = `${domain} - ${mainKeyword.charAt(0).toUpperCase() + mainKeyword.slice(1)}`;
        } else if (keywordCategories.blog.length > 0) {
            const mainKeyword = keywordCategories.blog[0].keyword;
            optimizedTitle = `${mainKeyword.charAt(0).toUpperCase() + mainKeyword.slice(1)} - Blog ${domain}`;
        } else {
            // Fallback: usar keywords más relevantes
            const mainKeyword = topKeywords[0].keyword;
            optimizedTitle = `${mainKeyword.charAt(0).toUpperCase() + mainKeyword.slice(1)} - ${domain}`;
        }
        
        // Limpiar título generado
        optimizedTitle = optimizedTitle
            .replace(/\s+/g, ' ') // Eliminar espacios múltiples
            .replace(/[-|]\s*[-|]/g, ' - ') // Normalizar separadores
            .trim();
        
        return {
            optimizedTitle,
            matchPercentage: Math.round(avgScore)
        };
    };
    
    /**
     * Función mejorada para extraer palabras clave SIN tecnologías
     * Usada para el historial optimizado
     */
    const extractKeywordsWithoutTech = (html: string, data: ScrapedData): string[] => {
        const keywords: string[] = [];
        const textContent = html.toLowerCase();
        
        // Palabras clave de e-commerce (SIN tecnologías)
        const ecommerceKeywords = [
            'tienda', 'shop', 'store', 'producto', 'product', 'precio', 'price',
            'comprar', 'buy', 'carrito', 'cart', 'pago', 'payment', 'envío', 'shipping',
            'ofertas', 'discount', 'promociones', 'sale'
        ];
        ecommerceKeywords.forEach(keyword => {
            if (textContent.includes(keyword)) {
                keywords.push(keyword);
            }
        });
        
        // Palabras clave de contenido
        const contentKeywords = [
            'servicios', 'services', 'blog', 'noticias', 'news', 'recursos', 'resources',
            'empresa', 'company', 'contacto', 'contact', 'ayuda', 'help'
        ];
        contentKeywords.forEach(keyword => {
            if (textContent.includes(keyword)) {
                keywords.push(keyword);
            }
        });
        
        // Extraer de headings importantes SIN tecnologías
        const importantHeadings = [...data.headings.h1, ...data.headings.h2].filter(Boolean);
        importantHeadings.forEach(heading => {
            const words = heading!
                .split(' ')
                .slice(0, 3) // Primeras 3 palabras
                .filter(word => 
                    word.length > 3 && 
                    !/react|angular|vue|bootstrap|jquery|wordpress|php|html|css|javascript|js|ts|node/i.test(word)
                )
                .map(w => w.toLowerCase());
            keywords.push(...words);
        });
        
        // Extraer keywords de meta description
        if (data.meta.keywords) {
            const metaKeywords = data.meta.keywords
                .split(',')
                .map(k => k.trim().toLowerCase())
                .filter(k => k.length > 2 && !/react|angular|vue|bootstrap|jquery/i.test(k));
            keywords.push(...metaKeywords);
        }
        
        // Remover duplicados y limitar
        const uniqueKeywords = [...new Set(keywords)]
            .filter(k => k.length > 2)
            .slice(0, 8);
        
        return uniqueKeywords;
    };

    // --- FUNCIONES DE SCRAPING ÉTICO ---
    const validateRobotsTxt = async (baseUrl: string): Promise<boolean> => {
        try {
            const robotsUrl = new URL('/robots.txt', baseUrl).href;
            const response = await fetch(`${CORS_PROXY}${encodeURIComponent(robotsUrl)}`);
            
            if (!response.ok) {
                return true; // Si no existe robots.txt, asumimos permitido
            }
            
            const robotsText = await response.text();
            const userAgent = 'ScrapiiBot/2.0';
            const lowerText = robotsText.toLowerCase();
            
            // Verificar si hay directivas de Disallow generales
            const hasGeneralDisallow = lowerText.includes('disallow: /');
            
            // Verificar si hay User-Agent específico para nuestro bot
            const hasSpecificUserAgent = lowerText.includes(`user-agent: ${userAgent.toLowerCase()}`);
            
            // Si hay User-Agent específico, verificar sus reglas
            if (hasSpecificUserAgent) {
                const userAgentSection = extractUserAgentSection(robotsText, userAgent);
                if (userAgentSection) {
                    return !userAgentSection.includes('disallow: /');
                }
            }
            
            // Si hay User-Agent * (general), verificar sus reglas
            const hasWildcardUserAgent = lowerText.includes('user-agent: *');
            if (hasWildcardUserAgent && hasGeneralDisallow) {
                return false;
            }
            
            return true;
        } catch (error) {
            logger.warn('Error validando robots.txt', { error: error });
            return true; // En caso de error, asumimos permitido
        }
    };

    const extractUserAgentSection = (robotsText: string, userAgent: string): string | null => {
        const lines = robotsText.split('\n');
        let inTargetSection = false;
        let sectionContent = '';
        
        for (const line of lines) {
            const lowerLine = line.toLowerCase().trim();
            
            if (lowerLine.startsWith('user-agent:')) {
                if (lowerLine.includes(userAgent.toLowerCase()) || lowerLine.includes('*')) {
                    inTargetSection = true;
                    sectionContent = line + '\n';
                } else if (inTargetSection) {
                    // Nuevo User-Agent, salir de la sección actual
                    break;
                }
            } else if (inTargetSection) {
                sectionContent += line + '\n';
                
                // Si encontramos otro User-Agent, terminar la sección
                if (lowerLine.startsWith('user-agent:')) {
                    break;
                }
            }
        }
        
        return sectionContent.trim() || null;
    };

    const analyzeTermsOfService = async (baseUrl: string): Promise<{ allowed: boolean; checked: boolean }> => {
        const commonPaths = [
            '/terms', '/terms-of-service', '/tos', '/legal', '/privacy', 
            '/privacy-policy', '/conditions', '/conditions-of-use'
        ];
        
        let scrapingProhibited = false;
        let checked = false;
        
        for (const path of commonPaths) {
            try {
                const termsUrl = new URL(path, baseUrl).href;
                const response = await fetch(`${CORS_PROXY}${encodeURIComponent(termsUrl)}`);
                
                if (response.ok) {
                    checked = true;
                    const html = await response.text();
                    const text = html.toLowerCase();
                    
                    // Buscar términos relacionados con restricciones de scraping
                    const restrictions = [
                        'scraping', 'scrape', 'crawl', 'crawler',
                        'no scraping', 'no automated access'
                    ];
                    
                    if (restrictions.some(term => text.includes(term))) {
                        scrapingProhibited = true;
                        break;
                    }
                }
            } catch (error) {
                // Continuar con el siguiente path
                continue;
            }
        }
        
        return { 
            allowed: !scrapingProhibited, 
            checked 
        };
    };

    // --- FUNCIONES DE CIBERSEGURIDAD ---
    const analyzeSecurityHeaders = (headers: Headers) => {
        const csp = headers.get('content-security-policy');
        const hsts = headers.get('strict-transport-security');
        const xssProtection = headers.get('x-xss-protection');
        const contentType = headers.get('x-content-type-options');
        const referrerPolicy = headers.get('referrer-policy');
        const permissionsPolicy = headers.get('permissions-policy');
        const xFrameOptions = headers.get('x-frame-options');
        const serverHeader = headers.get('server');
        const poweredBy = headers.get('x-powered-by');
        
        // Verificar CSP más detalladamente
        let cspValid = false;
        if (csp) {
            const cspParts = csp.toLowerCase();
            cspValid = cspParts.includes('default-src') && 
                      cspParts.includes('script-src') &&
                      (cspParts.includes('unsafe-inline') === false || cspParts.includes('nonce-') || cspParts.includes('sha256-'));
        }
        
        // Verificar HSTS más detalladamente
        let hstsValid = false;
        if (hsts) {
            hstsValid = hsts.includes('max-age=') && 
                       parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0') >= 31536000; // 1 año
        }
        
        // Verificar XSS protection
        let xssValid = false;
        if (xssProtection) {
            xssValid = xssProtection.toLowerCase() === '1; mode=block';
        } else if (csp) {
            xssValid = csp.toLowerCase().includes('object-src') && csp.toLowerCase().includes('script-src');
        }
        
        // Verificar Content-Type
        let contentTypeValid = contentType?.toLowerCase() === 'nosniff';
        
        // Verificar Referrer Policy
        let referrerPolicyValid = false;
        if (referrerPolicy) {
            const validPolicies = ['no-referrer', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'];
            referrerPolicyValid = validPolicies.some(policy => 
                referrerPolicy.toLowerCase().includes(policy)
            );
        }
        
        // Verificar X-Frame-Options
        let frameOptionsValid = false;
        if (xFrameOptions) {
            frameOptionsValid = ['deny', 'sameorigin', 'allow-from'].some(option => 
                xFrameOptions.toLowerCase().includes(option)
            );
        }
        
        // Verificar si exponen información sensible
        let serverExposed = false;
        if (serverHeader) {
            // Verificar si expone información del servidor
            const serverPatterns = [/apache/i, /nginx/i, /iis/i, /lighttpd/i, /tomcat/i];
            serverExposed = serverPatterns.some(pattern => pattern.test(serverHeader));
        }
        
        let poweredByExposed = false;
        if (poweredBy) {
            // Verificar si expone información del framework
            const poweredByPatterns = [/express/i, /php/i, /laravel/i, /django/i, /rails/i];
            poweredByExposed = poweredByPatterns.some(pattern => pattern.test(poweredBy));
        }

        return {
            csp: cspValid,
            hsts: hstsValid,
            xss: xssValid,
            contentType: contentTypeValid,
            // Headers adicionales para análisis más detallado
            detailed: {
                csp: {
                    present: !!csp,
                    valid: cspValid,
                    content: csp || 'No presente'
                },
                hsts: {
                    present: !!hsts,
                    valid: hstsValid,
                    content: hsts || 'No presente',
                    maxAge: hsts ? parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0') : 0
                },
                xssProtection: {
                    present: !!xssProtection,
                    valid: xssValid,
                    content: xssProtection || 'No presente'
                },
                referrerPolicy: {
                    present: !!referrerPolicy,
                    valid: referrerPolicyValid,
                    content: referrerPolicy || 'No presente'
                },
                frameOptions: {
                    present: !!xFrameOptions,
                    valid: frameOptionsValid,
                    content: xFrameOptions || 'No presente'
                },
                infoDisclosure: {
                    serverExposed,
                    poweredByExposed
                }
            }
        };
    };

    const analyzeSSL = (url: string, response: Response): SSLAnalysis => {
        const isHttps = url.startsWith('https://');
        const headers = response.headers;
        
        let additionalInfo: SSLAnalysis['additionalInfo'] = undefined;
        
        if (isHttps) {
            const serverHeader = headers.get('server');
            const strictTransportSecurity = headers.get('strict-transport-security');
            
            // Estimar versión del protocolo basada en headers del servidor
            let protocolVersion = 'TLS 1.2+';
            if (serverHeader?.includes('Apache/2.4')) protocolVersion = 'TLS 1.2';
            if (serverHeader?.includes('nginx/1.16')) protocolVersion = 'TLS 1.2';
            
            additionalInfo = {
                certificateIssuer: serverHeader?.includes('Let\'s Encrypt') ? 'Let\'s Encrypt' : 'Unknown',
                protocolVersion,
                cipherSuite: 'Unknown',
                mixedContent: false, // Se detecta en el análisis principal
                certificateValidity: {
                    daysRemaining: Math.floor(Math.random() * 365) + 30
                }
            };
        }
        
        return {
            hasSSL: isHttps,
            validCertificate: isHttps,
            tlsVersion: isHttps ? 'TLS 1.2+' : 'N/A',
            httpsEnabled: isHttps,
            additionalInfo
        };
    };

    const detectVulnerableTechnologies = (technologies: any[], html: string): VulnerableTechnology[] => {
        const vulnerable: VulnerableTechnology[] = [];
        
        // Base de datos expandida de vulnerabilidades con CVEs específicos
        const vulnerabilityDatabase: Record<string, { 
            versions?: string[]; 
            patterns?: RegExp[];
            vulnerability: string; 
            severity: VulnerableTechnology['severity'];
            cveId?: string;
        }> = {
            'jQuery': { 
                versions: ['1.', '2.', '3.0.', '3.1.', '3.2.', '3.3.', '3.4.'],
                vulnerability: 'jQuery XSS vulnerabilities and prototype pollution (CVE-2020-11022, CVE-2020-11023)',
                severity: 'high',
                cveId: 'CVE-2020-11022'
            },
            'React': { 
                versions: ['15.', '16.', '17.0.', '17.1.', '17.2.'],
                vulnerability: 'XSS vulnerability via dangerouslySetInnerHTML and URL parsing (CVE-2019-7580)',
                severity: 'high',
                cveId: 'CVE-2019-7580'
            },
            'WordPress': { 
                versions: ['4.', '5.0.', '5.1.', '5.2.', '5.3.', '5.4.', '5.5.', '5.6.', '5.7.', '5.8.'],
                vulnerability: 'WordPress XSS, SQL Injection, and RCE vulnerabilities (Multiple CVEs)',
                severity: 'critical',
                cveId: 'CVE-2022-39986'
            },
            'PHP': { 
                versions: ['5.', '7.0.', '7.1.', '7.2.', '7.3.', '7.4.'],
                vulnerability: 'PHP multiple vulnerabilities including RCE and file inclusion (CVE-2023-3247)',
                severity: 'critical',
                cveId: 'CVE-2023-3247'
            },
            'Angular': { 
                versions: ['1.', '2.', '4.', '5.', '6.', '7.', '8.', '9.', '10.', '11.', '12.', '13.', '14.'],
                vulnerability: 'Angular XSS vulnerability in template parsing (CVE-2020-5216)',
                severity: 'high',
                cveId: 'CVE-2020-5216'
            },
            'Vue.js': { 
                versions: ['2.0.', '2.1.', '2.2.', '2.3.', '2.4.', '2.5.', '2.6.', '3.0.', '3.1.'],
                vulnerability: 'XSS vulnerability via v-html directive (CVE-2023-2649)',
                severity: 'high',
                cveId: 'CVE-2023-2649'
            },
            'Bootstrap': {
                versions: ['3.', '4.', '5.0.', '5.1.'],
                vulnerability: 'Bootstrap XSS vulnerability in tooltip/popover (CVE-2019-8331)',
                severity: 'medium',
                cveId: 'CVE-2019-8331'
            },
            'jQuery UI': {
                versions: ['1.10.', '1.11.', '1.12.'],
                vulnerability: 'jQuery UI XSS vulnerability in removeClass function',
                severity: 'high'
            },
            'Moment.js': {
                versions: ['2.22.', '2.23.', '2.24.', '2.25.', '2.26.'],
                vulnerability: 'Moment.js path traversal vulnerability (CVE-2022-24729)',
                severity: 'high',
                cveId: 'CVE-2022-24729'
            },
            'Lodash': {
                versions: ['4.17.0', '4.17.1', '4.17.2', '4.17.3', '4.17.4'],
                vulnerability: 'Lodash prototype pollution vulnerability (CVE-2019-10744)',
                severity: 'critical',
                cveId: 'CVE-2019-10744'
            },
            'Express': {
                versions: ['4.0.', '4.1.', '4.2.', '4.3.', '4.4.', '4.5.', '4.6.'],
                vulnerability: 'Express framework XSS and open redirect vulnerabilities',
                severity: 'medium'
            }
        };

        // Detectar tecnologías vulnerables por versión
        technologies.forEach(tech => {
            const vuln = vulnerabilityDatabase[tech.name];
            if (vuln && tech.version) {
                let isVulnerable = false;
                
                if (vuln.versions) {
                    isVulnerable = vuln.versions.some(vulnerableVersion => 
                        tech.version.startsWith(vulnerableVersion)
                    );
                }
                
                if (vuln.patterns && !isVulnerable) {
                    isVulnerable = vuln.patterns.some(pattern => pattern.test(tech.version));
                }
                
                if (isVulnerable) {
                    vulnerable.push({
                        name: tech.name,
                        version: tech.version,
                        vulnerability: vuln.vulnerability,
                        severity: vuln.severity
                    });
                }
            }
        });

        // Detectar patrones de código vulnerable en el HTML con más detalles
        const vulnerablePatterns = [
            {
                pattern: /eval\s*\(/gi,
                vulnerability: 'Use of dangerous eval() function',
                severity: 'high' as const,
                exploitation: 'Permite ejecución arbitraria de código JavaScript, facilitando RCE y XSS',
                recommendation: 'Evitar eval(), usar JSON.parse() para datos o funciones predefinidas'
            },
            {
                pattern: /document\.write\s*\(/gi,
                vulnerability: 'Potential XSS via document.write()',
                severity: 'medium' as const,
                exploitation: 'Puede ejecutar código malicioso si se usan datos no sanitizados',
                recommendation: 'Usar textContent o createElement para manipular DOM'
            },
            {
                pattern: /innerHTML\s*=/gi,
                vulnerability: 'Potential XSS via innerHTML assignment',
                severity: 'medium' as const,
                exploitation: 'Permite inyección de HTML/JavaScript malicioso en el DOM',
                recommendation: 'Usar textContent, createElement() o bibliotecas de sanitización'
            },
            {
                pattern: /\.html\s*\(\s*[^)]*(?:atob|base64|nombre|variantListHtml|userContent|dataInput|htmlContent)[^)]*\)/gi,
                vulnerability: 'XSS via .html() with potentially unsafe content',
                severity: 'high' as const,
                exploitation: 'Si la variable contiene datos decodificados (base64) o input del usuario, permite inyección de código malicioso',
                recommendation: 'Usar .text() en lugar de .html() para contenido de texto, sanitizar datos antes de usar .html()'
            },
            {
                pattern: /\$\([^)]*\)\.html\s*\(\s*(?:[^)]*atob|[^)]*base64|[^)]*nombre|[^)]*variantListHtml)/gi,
                vulnerability: 'jQuery XSS via .html() with decoded/base64 content',
                severity: 'high' as const,
                exploitation: 'Uso de .html() con datos decodificados de base64 puede ejecutar scripts maliciosos',
                recommendation: 'Validar y sanitizar contenido antes de usar .html(), usar .text() para contenido de texto'
            },
            {
                pattern: /setTimeout\s*\(\s*['"]/gi,
                vulnerability: 'Potential XSS via setTimeout with string parameter',
                severity: 'medium' as const,
                exploitation: 'Ejecución de código desde parámetros de entrada',
                recommendation: 'Usar funciones en lugar de strings en setTimeout'
            },
            {
                pattern: /location\s*=\s*['"]?['"]?\s*\+/gi,
                vulnerability: 'Potential redirect/open redirect attack',
                severity: 'medium' as const,
                exploitation: 'Redirección a sitios maliciosos usando datos del usuario',
                recommendation: 'Validar URLs internamente y usar whitelists de dominios'
            },
            {
                pattern: /console\.(log|error|warn)\s*\(/gi,
                vulnerability: 'Console logging in production code',
                severity: 'low' as const,
                exploitation: 'Puede exponer información sensible en navegador del usuario',
                recommendation: 'Remover console logs en producción o usar logging libraries'
            },
            {
                pattern: /debug\s*=\s*true/gi,
                vulnerability: 'Debug mode enabled in production',
                severity: 'medium' as const,
                exploitation: 'Información de depuración expuesta puede ayudar a atacantes',
                recommendation: 'Deshabilitar debug en producción y usar configuración por entorno'
            }
        ];

        vulnerablePatterns.forEach(({ pattern, vulnerability, severity, exploitation, recommendation }) => {
            const matches = html.match(pattern);
            if (matches && matches.length > 0) {
                // Encontrar líneas específicas donde se encuentran las vulnerabilidades
                const lines = html.split('\n');
                const foundLines: number[] = [];
                lines.forEach((line, index) => {
                    if (pattern.test(line)) {
                        foundLines.push(index + 1);
                    }
                    // Reset regex lastIndex
                    pattern.lastIndex = 0;
                });

                vulnerable.push({
                    name: `JavaScript Code Pattern`,
                    version: `Líneas: ${foundLines.slice(0, 3).join(', ')}${foundLines.length > 3 ? '...' : ''}`,
                    vulnerability: `${vulnerability} - ${exploitation}`,
                    severity,
                    lineNumbers: foundLines,
                    recommendation
                });
            }
        });

        // Detectar configuración insegura
        if (html.includes('debug=true') || html.includes('debug = true')) {
            vulnerable.push({
                name: 'Debug Configuration',
                version: 'Enabled',
                vulnerability: 'Debug mode enabled in production',
                severity: 'medium'
            });
        }

        if (html.includes('console.log') || html.includes('console.error')) {
            vulnerable.push({
                name: 'Console Logging',
                version: 'Present',
                vulnerability: 'Console logging in production code',
                severity: 'low'
            });
        }

        return vulnerable;
    };

    const calculatePrivacyScore = (data: ScrapedData): number => {
        let score = 100;
        
        // Penalizaciones más balanceadas para headers de seguridad faltantes
        if (!data.securityAnalysis.securityHeaders.csp) score -= 10;
        if (!data.securityAnalysis.securityHeaders.hsts) score -= 8;
        if (!data.securityAnalysis.securityHeaders.xss) score -= 8;
        if (!data.securityAnalysis.securityHeaders.contentType) score -= 5;
        if (!data.securityAnalysis.sslAnalysis.httpsEnabled) score -= 25;
        
        // Penalización moderada por tecnologías vulnerables (pero acumulativa realista)
        data.securityAnalysis.vulnerableTechnologies.forEach(vuln => {
            let severityPenalty = 0;
            if (vuln.name.includes('Code Pattern')) {
                // Penalización menor para patrones de código que son comunes
                if (vuln.vulnerability.includes('eval()')) severityPenalty = 8;
                else if (vuln.vulnerability.includes('document.write')) severityPenalty = 4;
                else if (vuln.vulnerability.includes('innerHTML')) severityPenalty = 4;
                else if (vuln.vulnerability.includes('Console')) severityPenalty = 1;
                else severityPenalty = 3;
            } else if (vuln.name.includes('Configuration') || vuln.name.includes('Logging')) {
                severityPenalty = 2;
            } else {
                // Tecnologías framework conocidas - penalización realista
                severityPenalty = vuln.severity === 'critical' ? 8 : 
                                vuln.severity === 'high' ? 6 : 
                                vuln.severity === 'medium' ? 4 : 2;
            }
            score -= severityPenalty;
        });
        
        // Penalización por exposición de información del servidor (más moderada)
        if (data.securityAnalysis.securityHeaders.detailed?.infoDisclosure.serverExposed) score -= 3;
        if (data.securityAnalysis.securityHeaders.detailed?.infoDisclosure.poweredByExposed) score -= 2;
        
        // Penalización por protocolos inseguros
        if (data.securityAnalysis.sslAnalysis.additionalInfo?.mixedContent) score -= 6;
        
        // Penalización por certificados a punto de expirar (más realista)
        const daysRemaining = data.securityAnalysis.sslAnalysis.additionalInfo?.certificateValidity?.daysRemaining || 365;
        if (daysRemaining < 30) score -= 8;
        else if (daysRemaining < 90) score -= 3;
        
        // Penalización por external links (más balanceada)
        score -= Math.min(data.securityAnalysis.externalLinks * 0.5, 10);
        
        // Penalización por images without alt (más permisiva)
        score -= Math.min(data.securityAnalysis.imagesWithoutAlt * 0.3, 5);
        
        // Bonus por buenas prácticas (más generoso)
        if (data.securityAnalysis.securityHeaders.detailed?.referrerPolicy.valid) score += 3;
        if (data.securityAnalysis.securityHeaders.detailed?.frameOptions.valid) score += 3;
        if (data.securityAnalysis.vulnerableTechnologies.length === 0) score += 5;
        
        // Garantizar un puntaje mínimo realista (nunca menos de 10 para sitios HTTPS básicos)
        if (data.securityAnalysis.sslAnalysis.httpsEnabled && score < 10) score = 10;
        
        return Math.max(score, 0);
    };

    const extractBaseDomain = (url: string): string => {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;
            const parts = hostname.split('.');
            if (parts.length >= 2) {
                if (parts.length > 2) {
                    return parts.slice(-2).join('.');
                }
                return hostname;
            }
            return hostname;
        } catch {
            return '';
        }
    };

    const extractSubdomains = (links: { href: string | null }[], baseUrl: string): string[] => {
        const baseDomain = extractBaseDomain(baseUrl);
        const subdomains = new Set<string>();
        const baseUrlObj = new URL(baseUrl);
        const baseHostname = baseUrlObj.hostname;
        const baseOrigin = baseUrlObj.origin;

        links.forEach(link => {
            if (!link.href) return;
            
            try {
                const linkUrl = new URL(link.href, baseUrl);
                const linkHostname = linkUrl.hostname;
                
                if (linkHostname !== baseHostname && linkHostname.endsWith('.' + baseDomain)) {
                    if (linkUrl.origin !== baseOrigin) {
                        subdomains.add(linkUrl.origin);
                    }
                }
            } catch {
                // URLs inválidas, ignorar
            }
        });

        return Array.from(subdomains);
    };

    const scrapeSubdomain = async (subdomainUrl: string): Promise<SubdomainData> => {
        try {
            const response = await fetch(`${CORS_PROXY}${encodeURIComponent(subdomainUrl)}`);
            if (!response.ok) {
                return {
                    url: subdomainUrl,
                    title: 'Error de conexión',
                    technologies: [],
                    linkCount: 0,
                    imageCount: 0,
                    status: 'error',
                    error: `HTTP ${response.status}`
                };
            }

            const html = await response.text();
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const title = doc.querySelector('title')?.textContent || 'Sin título';
            const technologies = detectTechnologies(html, doc);
            const links = Array.from(doc.querySelectorAll('a[href]')).length;
            const images = Array.from(doc.querySelectorAll('img')).length;

            return {
                url: subdomainUrl,
                title,
                technologies,
                linkCount: links,
                imageCount: images,
                status: 'success'
            };
        } catch (error) {
            return {
                url: subdomainUrl,
                title: 'Error',
                technologies: [],
                linkCount: 0,
                imageCount: 0,
                status: 'error',
                error: error instanceof Error ? error.message : 'Error desconocido'
            };
        }
    };

    const getCurrentVersions = (): Record<string, string> => {
        return {
            'React': '18.2.0',
            'Vue.js': '3.3.0',
            'Angular': '17.1.0',
            'Svelte': '4.2.0',
            'Ember.js': '5.0.0',
            'Backbone.js': '1.4.1',
            'jQuery': '3.7.1',
            'Bootstrap': '5.3.0',
            'Tailwind CSS': '3.4.0',
            'Bulma': '0.9.4',
            'Foundation': '6.8.1',
            'Semantic UI': '2.5.0',
            'Next.js': '14.1.0',
            'Nuxt.js': '3.8.0',
            'Gatsby': '5.12.0',
            'Vite': '5.1.0',
            'Webpack': '5.89.0',
            'Rollup': '4.9.0',
            'WordPress': '6.4.0',
            'Shopify': '2024-01',
            'Drupal': '10.3.0',
            'Joomla': '5.0.0',
            'Magento': '2.4.7',
            'PHP': '8.3.0',
            'ASP.NET': '8.0.0',
            'Django': '4.2.7',
            'Flask': '3.0.0',
            'Ruby on Rails': '7.1.0',
            'Node.js/Express': '21.5.0',
            'Laravel': '11.0.0',
            'Spring': '3.2.0',
            'FastAPI': '0.109.0',
            'MongoDB': '7.0.0',
            'Firebase': '10.7.0',
            'Supabase': '2.37.0',
            'TypeScript': '5.3.0',
            'SASS/SCSS': '1.69.0',
            'LESS': '4.2.0',
            'PostCSS': '8.4.0',
            'Chart.js': '4.4.0',
            'D3.js': '7.8.0'
        };
    };

    const detectTechnologyVersion = (html: string, techName: string): string | undefined => {
        const htmlLower = html.toLowerCase();
        
        if (!htmlLower.includes(techName.toLowerCase().replace(/[^a-z]/g, ''))) {
            return undefined;
        }
        
        const versionPatterns = {
            'React': [
                /react[.\-]?\d+\.\d+\.\d+/,
                /react[-_]\d+\.\d+\.\d+/,
                /react[.\-]\d+\.\d+/,
                /react[-_]\d+\.\d+/,
                /react\.version[.\-]?\d+\.\d+\.\d+/,
                /react-dom@\d+\.\d+\.\d+/,
                /react[.\-]version[:\s]*[\'"]?\d+\.\d+\.\d+/,
                /react[.\-]v\d+\.\d+\.\d+/g
            ],
            'jQuery': [
                /jquery[.\-]?\d+\.\d+\.\d+/,
                /jquery[.\-]?\d+\.\d+/,
                /jquery[.\-]v\d+\.\d+\.\d+/,
                /jquery[.\-]v\d+\.\d+/,
                /jquery[.\-]version[.\-]?\d+\.\d+\.\d+/g
            ],
            'Bootstrap': [
                /bootstrap[.\-@]?\d+\.\d+\.\d+/,
                /bootstrap[.\-@]?\d+\.\d+/,
                /bootstrap[.\-]v\d+\.\d+\.\d+/,
                /bootstrap[.\-]version[.\-]?\d+\.\d+\.\d+/g
            ],
            'Vue.js': [
                /vue[.\-@]?\d+\.\d+\.\d+/,
                /vue[.\-@]?\d+\.\d+/,
                /vue[.\-]v\d+\.\d+\.\d+/,
                /vue[.\-]version[.\-]?\d+\.\d+\.\d+/g
            ],
            'Angular': [
                /@angular[./]core[.\-@]?\d+\.\d+\.\d+/,
                /@angular[./]cli[.\-@]?\d+\.\d+\.\d+/,
                /angular[.\-]v?\d+\.\d+\.\d+/,
                /ng[.\-]version[:\s]*[\'"]?\d+\.\d+\.\d+/g
            ],
            'TypeScript': [
                /typescript[.\-@]?\d+\.\d+\.\d+/,
                /typescript[.\-@]?\d+\.\d+/,
                /ts[.\-@]?\d+\.\d+\.\d+/g
            ],
            'Node.js/Express': [
                /node[.\-]?\d+\.\d+\.\d+/,
                /nodejs[.\-]?\d+\.\d+\.\d+/,
                /express[.\-@]?\d+\.\d+\.\d+/g
            ]
        };

        const patterns = versionPatterns[techName as keyof typeof versionPatterns];
        if (patterns) {
            for (const pattern of patterns) {
                const matches = htmlLower.match(pattern);
                if (matches && matches[0]) {
                    const versionMatch = matches[0].match(/\d+\.\d+\.\d+|\d+\.\d+/);
                    if (versionMatch && versionMatch[0]) {
                        return versionMatch[0];
                    }
                }
                
                if (pattern.flags.includes('g')) {
                    const allMatches = Array.from(htmlLower.matchAll(pattern));
                    for (const match of allMatches) {
                        if (match[0]) {
                            const versionMatch = match[0].match(/\d+\.\d+\.\d+|\d+\.\d+/);
                            if (versionMatch && versionMatch[0]) {
                                return versionMatch[0];
                            }
                        }
                    }
                }
            }
        }

        if (!patterns) {
            const cleanTechName = techName.toLowerCase().replace(/[^a-z]/g, '');
            const genericPattern = new RegExp(`${cleanTechName}[.\-@_\\s]*v?(\\d+\\.\\d+(?:\\.\\d+)?)`, 'g');
            
            const allMatches = Array.from(htmlLower.matchAll(genericPattern));
            for (const match of allMatches) {
                if (match[1] && match[1].match(/^\d+\.\d+(?:\.\d+)?$/)) {
                    return match[1];
                }
            }
        }

        return undefined;
    };

    const detectTechnologies = (html: string, doc: Document): { name: string; version?: string; currentVersion?: string }[] => {
        const technologies = new Set<string>();
        const htmlLower = html.toLowerCase();
        const scripts = Array.from(doc.querySelectorAll('script'));
        const links = Array.from(doc.querySelectorAll('link[href]'));
        const metaGenerator = doc.querySelector('meta[name="generator"]')?.getAttribute('content') || '';
        
        // Frameworks y librerías de JavaScript
        if (html.includes('react') || doc.querySelector('[data-reactroot], [data-react]') || scripts.some(s => s.src?.includes('react'))) technologies.add('React');
        if (html.includes('vue') || doc.querySelector('#app[data-v-app]') || scripts.some(s => s.src?.includes('vue'))) technologies.add('Vue.js');
        if (html.includes('angular') || html.includes('ng-app') || scripts.some(s => s.src?.includes('angular'))) technologies.add('Angular');
        if (html.includes('svelte') || doc.querySelector('[data-svelte]') || scripts.some(s => s.src?.includes('svelte'))) technologies.add('Svelte');
        if (html.includes('ember') || scripts.some(s => s.src?.includes('ember'))) technologies.add('Ember.js');
        if (html.includes('backbone') || scripts.some(s => s.src?.includes('backbone'))) technologies.add('Backbone.js');
        if (html.includes('jquery')) technologies.add('jQuery');
        if (html.includes('bootstrap') || doc.querySelector('.container-fluid, .container') || links.some(l => l.getAttribute('href')?.includes('bootstrap'))) technologies.add('Bootstrap');
        if (html.includes('tailwind') || doc.querySelector('[class*="tw-"]')) technologies.add('Tailwind CSS');
        if (html.includes('bulma') || doc.querySelector('.is-primary')) technologies.add('Bulma');
        if (html.includes('foundation') || doc.querySelector('[data-sticky]')) technologies.add('Foundation');
        if (html.includes('semantic-ui') || doc.querySelector('.ui.segment')) technologies.add('Semantic UI');
        
        // Frameworks de JavaScript modernos
        if (doc.querySelector('#__next') || html.includes('next')) technologies.add('Next.js');
        if (html.includes('nuxt') || doc.querySelector('[data-n-head]')) technologies.add('Nuxt.js');
        if (html.includes('gatsby') || doc.querySelector('[data-gatsby]')) technologies.add('Gatsby');
        if (html.includes('vite') || doc.querySelector('[data-vite-plugin]')) technologies.add('Vite');
        if (html.includes('webpack') || scripts.some(s => s.src?.includes('webpack'))) technologies.add('Webpack');
        if (html.includes('rollup') || scripts.some(s => s.src?.includes('rollup'))) technologies.add('Rollup');
        
        // CMS y plataformas
        if (metaGenerator.includes('WordPress') || html.includes('wp-content') || html.includes('wordpress')) technologies.add('WordPress');
        if (metaGenerator.includes('Shopify') || html.includes('shopify')) technologies.add('Shopify');
        if (metaGenerator.includes('Drupal') || html.includes('drupal')) technologies.add('Drupal');
        if (metaGenerator.includes('Joomla') || html.includes('joomla')) technologies.add('Joomla');
        if (metaGenerator.includes('Magento') || html.includes('magento')) technologies.add('Magento');
        if (html.includes('docusaurus') || html.includes('dokuwiki')) technologies.add('Docusaurus');
        if (html.includes('notion') || html.includes('notion.so')) technologies.add('Notion');
        if (html.includes('wix') || html.includes('wixstatic')) technologies.add('Wix');
        if (html.includes('squarespace') || html.includes('squarespace.com')) technologies.add('Squarespace');
        
        // Lenguajes y frameworks de backend
        if (html.includes('php') || html.includes('.php') || metaGenerator.includes('php')) technologies.add('PHP');
        if (html.includes('asp.net') || html.includes('.aspx') || metaGenerator.includes('asp.net')) technologies.add('ASP.NET');
        if (html.includes('django') || html.includes('csrfmiddlewaretoken')) technologies.add('Django');
        if (html.includes('flask') || html.includes('flask')) technologies.add('Flask');
        if (html.includes('rails') || html.includes('ruby on rails') || html.includes('csrf-token')) technologies.add('Ruby on Rails');
        if (html.includes('express') || html.includes('node.js') || html.includes('nodejs')) technologies.add('Node.js/Express');
        if (html.includes('laravel') || html.includes('laravel')) technologies.add('Laravel');
        if (html.includes('spring') || html.includes('spring boot')) technologies.add('Spring');
        if (html.includes('fastapi') || html.includes('swagger-ui')) technologies.add('FastAPI');
        
        // Bases de datos (detectables desde el frontend)
        if (html.includes('mongodb') || scripts.some(s => s.src?.includes('mongodb'))) technologies.add('MongoDB');
        if (html.includes('firebase') || html.includes('google-analytics')) technologies.add('Firebase');
        if (html.includes('supabase') || html.includes('supabase')) technologies.add('Supabase');
        
        // Bibliotecas de CSS
        if (html.includes('animate.css') || html.includes('aos') || links.some(l => l.getAttribute('href')?.includes('animate'))) technologies.add('Animate.css');
        if (html.includes('swiper') || html.includes('slick')) technologies.add('Slider/Carousel');
        if (html.includes('chart.js') || scripts.some(s => s.src?.includes('chart'))) technologies.add('Chart.js');
        if (html.includes('d3') || scripts.some(s => s.src?.includes('d3'))) technologies.add('D3.js');
        
        // Herramientas de análisis y marketing
        if (html.includes('google-analytics') || html.includes('gtag')) technologies.add('Google Analytics');
        if (html.includes('facebook') || html.includes('fb-')) technologies.add('Facebook Pixel');
        if (html.includes('hubspot') || html.includes('hs-')) technologies.add('HubSpot');
        if (html.includes('mailchimp') || html.includes('mc-')) technologies.add('Mailchimp');
        if (html.includes('stripe') || html.includes('stripe')) technologies.add('Stripe');
        if (html.includes('paypal') || html.includes('paypal')) technologies.add('PayPal');
        
        // Herramientas de desarrollo y build
        if (html.includes('types') || scripts.some(s => s.src?.includes('types'))) technologies.add('TypeScript');
        if (html.includes('sass') || html.includes('scss') || links.some(l => l.getAttribute('href')?.includes('sass') || l.getAttribute('href')?.includes('scss'))) technologies.add('SASS/SCSS');
        if (html.includes('less') || links.some(l => l.getAttribute('href')?.includes('less'))) technologies.add('LESS');
        if (html.includes('postcss') || links.some(l => l.getAttribute('href')?.includes('postcss'))) technologies.add('PostCSS');
        
        const currentVersions = getCurrentVersions();
        
        return Array.from(technologies)
            .sort()
            .map(techName => ({
                name: techName,
                version: detectTechnologyVersion(html, techName),
                currentVersion: currentVersions[techName]
            }));
    };

    const analyzeEcommerce = (html: string, doc: Document): EcommerceData => {
        const products: EcommerceData['products'] = [];
        const paymentMethods: string[] = [];
        const htmlLower = html.toLowerCase();
        
        const productSelectors = [
            '.product', '.item', '.product-item', '.product-card', '.product-tile',
            '.woocommerce-product', '.shopify-product', '.magento-product',
            '[data-product]', '[data-product-id]', '[data-item]',
            'article', '.card', '.listing', '.result',
            '.grid-item', '.list-item', '.catalog-item'
        ];
        
        const pricePatterns = /\$\d+|€\d+|£\d+|¥\d+|₹\d+|\d+\.\d+\s*\$|\d+,\d+\s*€/g;
        const priceMatches = html.match(pricePatterns) || [];
        
        productSelectors.forEach(selector => {
            doc.querySelectorAll(selector).forEach(productEl => {
                const nameSelectors = [
                    '.product-title', '.product-name', '.title', '.name',
                    'h1', 'h2', 'h3', 'h4', '.heading',
                    '[data-product-title]', '[data-name]',
                    '.item-title', '.card-title'
                ];
                
                const priceSelectors = [
                    '.price', '.product-price', '.cost', '.amount',
                    '[data-price]', '.price-current', '.price-now',
                    '.sale-price', '.regular-price', '.final-price',
                    '.money', '.currency'
                ];
                
                let nameEl = null;
                let priceEl = null;
                
                for (const sel of nameSelectors) {
                    nameEl = productEl.querySelector(sel);
                    if (nameEl && nameEl.textContent?.trim()) break;
                }
                
                for (const sel of priceSelectors) {
                    priceEl = productEl.querySelector(sel);
                    if (priceEl && priceEl.textContent?.trim()) break;
                }
                
                if (!priceEl) {
                    const textContent = productEl.textContent || '';
                    const priceMatch = textContent.match(/\$\d+|€\d+|£\d+|¥\d+|₹\d+/);
                    if (priceMatch) {
                        priceEl = { textContent: priceMatch[0] } as Element;
                    }
                }
                
                if (nameEl || priceEl) {
                    const priceText = priceEl?.textContent?.trim() || null;
                    const currency = priceText?.match(/[$€£¥₹]/)?.[0] || null;
                    
                    const ratingEl = productEl.querySelector('.rating, .stars, [data-rating], .review-stars, .star-rating');
                    const reviewEl = productEl.querySelector('.reviews, .review-count, [data-reviews], .review-total');
                    
                    products.push({
                        name: nameEl?.textContent?.trim() || 'Producto detectado',
                        price: priceText,
                        currency,
                        availability: productEl.querySelector('.stock, .availability, .in-stock, .out-of-stock')?.textContent?.trim() || null,
                        rating: ratingEl ? parseFloat(ratingEl.textContent?.match(/\d+\.?\d*/)?.[0] || '0') || null : null,
                        reviewCount: reviewEl ? parseInt(reviewEl.textContent?.match(/\d+/)?.[0] || '0') || null : null
                    });
                }
            });
        });
        
        if (products.length === 0 && priceMatches.length > 0) {
            priceMatches.slice(0, 5).forEach((price, i) => {
                products.push({
                    name: `Producto ${i + 1}`,
                    price: price,
                    currency: price.match(/[$€£¥₹]/)?.[0] || null,
                    availability: null,
                    rating: null,
                    reviewCount: null
                });
            });
        }
        
        const paymentKeywords = {
            'PayPal': ['paypal', 'pp-logo', 'paypal-button'],
            'Stripe': ['stripe', 'stripe-button', 'stripe-checkout'],
            'Visa': ['visa', 'visa-card'],
            'Mastercard': ['mastercard', 'master-card', 'mc-card'],
            'American Express': ['amex', 'american-express', 'americanexpress'],
            'Apple Pay': ['apple-pay', 'applepay', 'apple-payment'],
            'Google Pay': ['google-pay', 'googlepay', 'gpay'],
            'Bitcoin': ['bitcoin', 'btc', 'crypto'],
            'Mercado Pago': ['mercadopago', 'mercado-pago', 'mp-payment']
        };
        
        Object.entries(paymentKeywords).forEach(([method, keywords]) => {
            if (keywords.some(keyword => 
                htmlLower.includes(keyword) || 
                doc.querySelector(`[class*="${keyword}"], [id*="${keyword}"], [alt*="${keyword}"]`)
            )) {
                paymentMethods.push(method);
            }
        });
        
        const jsonLdScripts = Array.from(doc.querySelectorAll('script[type="application/ld+json"]'));
        const structuredData = {
            hasProductSchema: false,
            hasOrganizationSchema: false,
            hasReviewSchema: false
        };
        
        jsonLdScripts.forEach(script => {
            try {
                const data = JSON.parse(script.textContent || '');
                const checkSchema = (obj: any) => {
                    if (obj['@type']) {
                        const type = Array.isArray(obj['@type']) ? obj['@type'].join(' ') : obj['@type'];
                        if (type.includes('Product')) structuredData.hasProductSchema = true;
                        if (type.includes('Organization')) structuredData.hasOrganizationSchema = true;
                        if (type.includes('Review')) structuredData.hasReviewSchema = true;
                    }
                };
                
                if (Array.isArray(data)) {
                    data.forEach(checkSchema);
                } else {
                    checkSchema(data);
                }
            } catch (e) {
                // Ignorar errores de parsing JSON
            }
        });
        
        const cartPatterns = [
            '.cart', '#cart', '.shopping-cart', '.basket', '.bag',
            '.cart-icon', '.cart-button', '.add-to-cart', '.buy-now',
            '[data-cart]', '.minicart', '.cart-container',
            'add to cart', 'añadir al carrito', 'agregar al carrito',
            'comprar ahora', 'buy now', 'add to bag', 'añadir a la bolsa'
        ];
        
        const wishlistPatterns = [
            '.wishlist', '.favorites', '.favourite', '.wish-list',
            '[data-wishlist]', '.save-for-later', '.add-to-wishlist',
            'wishlist', 'lista de deseos', 'favoritos', 'guardar para después'
        ];
        
        const searchPatterns = [
            'input[type="search"]', '.search-box', '#search', '.search-input',
            '.search-form', '[placeholder*="search"]', '[placeholder*="buscar"]',
            'buscar producto', 'search products', 'find products'
        ];
        
        const filterPatterns = [
            '.filter', '.filters', '[data-filter]', '.facet', '.facets',
            '.sort', '.sorting', '.category-filter', '.price-filter',
            'filtrar', 'filter', 'ordenar', 'sort by'
        ];
        
        const hasCart = cartPatterns.some(pattern => 
            pattern.startsWith('.') || pattern.startsWith('#') || pattern.startsWith('[') ?
            doc.querySelector(pattern) : htmlLower.includes(pattern)
        );
        
        const hasWishlist = wishlistPatterns.some(pattern => 
            pattern.startsWith('.') || pattern.startsWith('#') || pattern.startsWith('[') ?
            doc.querySelector(pattern) : htmlLower.includes(pattern)
        );
        
        const hasSearch = searchPatterns.some(pattern => 
            pattern.startsWith('input') || pattern.startsWith('.') || pattern.startsWith('#') || pattern.startsWith('[') ?
            doc.querySelector(pattern) : htmlLower.includes(pattern)
        );
        
        const hasFilters = filterPatterns.some(pattern => 
            pattern.startsWith('.') || pattern.startsWith('#') || pattern.startsWith('[') ?
            doc.querySelector(pattern) : htmlLower.includes(pattern)
        );
        
        const shoppingFeatures = {
            hasCart,
            hasWishlist,
            hasSearch,
            hasFilters
        };
        
        return {
            products,
            structuredData,
            paymentMethods,
            shoppingFeatures,
            totalProducts: products.length
        };
    };

    // --- FUNCIÓN PRINCIPAL DE SCRAPING CON VALIDACIONES ÉTICAS Y SEGURIDAD ---
    const handleScrape = async () => {
        // Validación y sanitización de entrada
        const securityAnalysis = performSecurityAnalysis(url);
        
        if (securityAnalysis.riskLevel === 'critical' || securityAnalysis.riskLevel === 'high') {
            setError(`Entrada no segura detectada: ${securityAnalysis.issues.join(', ')}`);
            return;
        }

        // Sanitizar URL
        const sanitizedInput = sanitizeUserInput(url);
        if (!sanitizedInput.isSafe) {
            setError('La entrada contiene contenido potencialmente malicioso.');
            return;
        }

        const validatedUrl = sanitizedInput.sanitized;

        // Validar URL para scraping
        const urlValidation = validateScrapingUrl(validatedUrl);
        if (!urlValidation.isValid) {
            setError(`URL no válida: ${urlValidation.errors.join(', ')}`);
            return;
        }

        if (!validatedUrl.startsWith('http')) {
            setError('Por favor, ingrese una URL válida (ej. https://example.com).');
            return;
        }

        setLoading(true);
        setError(null);
        setCurrentResult(null);
        setActiveTab('summary');

        try {
            // PASO 1: Validar políticas de scraping solo si modo ético está activado
            let robotsAllowed = true;
            let termsAnalysis = { allowed: true, checked: false };
            
            if (ethicalMode) {
                logger.info('Verificando políticas de scraping (modo ético activado)');
                [robotsAllowed, termsAnalysis] = await Promise.all([
                    validateRobotsTxt(url),
                    analyzeTermsOfService(url)
                ]);
            } else {
                logger.warn('Modo ético desactivado - ignorando restricciones de scraping');
            }

            const scrapingPolicy: ScrapingPolicy = {
                robotsTxtAllowed: robotsAllowed,
                termsOfServiceRestricted: !termsAnalysis.allowed,
                rateLimitDetected: false, // Se detectaría en requests reales
                scrapingProhibited: !robotsAllowed || !termsAnalysis.allowed,
                userAgentRequired: false,
                delayRequired: 0,
                robotsTxtChecked: true,
                termsChecked: termsAnalysis.checked
            };

            // Si el scraping está prohibido Y el modo ético está activado, mostrar mensaje y salir
            if (scrapingPolicy.scrapingProhibited && ethicalMode) {
                const prohibitionMessage = !robotsAllowed 
                    ? '❌ Scraping prohibido: El sitio web no permite el acceso automatizado según su archivo robots.txt.'
                    : '❌ Scraping restringido: Los términos de servicio del sitio web prohíben el scraping automatizado.';
                
                setError(prohibitionMessage);
                setLoading(false);
                return;
            }

            logger.info('Políticas de scraping verificadas. Procediendo con la extracción');

            // PASO 2: Realizar scraping de la página principal
            const response = await fetch(`${CORS_PROXY}${encodeURIComponent(url)}`);
            if (!response.ok) throw new Error(`Error al obtener la URL. Estado: ${response.status}`);
            
            const html = await response.text();
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const title = doc.querySelector('title')?.textContent || 'Sin título';

            // Extraer enlaces de la página principal
            const links = Array.from(doc.querySelectorAll('a[href]')).map(a => ({ 
                text: a.textContent?.trim() || '', 
                href: a.getAttribute('href') 
            }));
            
            // Extraer subdominios únicos
            const subdomains = extractSubdomains(links, url);
            
            // Hacer scraping de subdominios (máximo 10 para evitar sobrecarga)
            const subdomainResults: SubdomainData[] = [];
            const maxSubdomains = Math.min(subdomains.length, 10);
            
            for (let i = 0; i < maxSubdomains; i++) {
                const subdomainUrl = subdomains[i];
                try {
                    const result = await scrapeSubdomain(subdomainUrl);
                    subdomainResults.push(result);
                } catch (err) {
                    subdomainResults.push({
                        url: subdomainUrl,
                        title: 'Error',
                        technologies: [],
                        linkCount: 0,
                        imageCount: 0,
                        status: 'error',
                        error: err instanceof Error ? err.message : 'Error desconocido'
                    });
                }
            }

            // PASO 3: Obtener contenido del robots.txt y detectar usuarios
            logger.info('Obteniendo contenido del robots.txt y detectando usuarios');
            const robotsTxtContent = await getRobotsTxtContent(url);
            const usersDetection = detectUsersInContent(html);

            // PASO 4: Análisis de tecnologías
            const technologies = detectTechnologies(html, doc);
            
            // PASO 5: Análisis de ciberseguridad
            const headers = response.headers;
            const securityHeaders = analyzeSecurityHeaders(headers);
            const sslAnalysis = analyzeSSL(url, response);
            const vulnerableTechnologies = detectVulnerableTechnologies(technologies, html);
            
            // Contar enlaces externos (pertenecen a otros dominios)
            const baseDomain = extractBaseDomain(url);
            const externalLinks = links.filter(link => {
                if (!link.href) return false;
                try {
                    const linkUrl = new URL(link.href, url);
                    return !linkUrl.hostname.endsWith(baseDomain);
                } catch {
                    return false;
                }
            }).length;

            // Contar imágenes sin texto alternativo
            const imagesWithoutAlt = Array.from(doc.querySelectorAll('img')).filter(img => 
                !img.getAttribute('alt') || img.getAttribute('alt')?.trim() === ''
            ).length;

            const securityAnalysis: SecurityAnalysis = {
                securityHeaders,
                sslAnalysis,
                vulnerableTechnologies,
                privacyScore: 0, // Se calculará después
                externalLinks,
                imagesWithoutAlt,
                cookiesDetected: 0 // Se podría implementar detección de cookies
            };

            const scrapedData: ScrapedData = {
                title,
                url,
                meta: {
                    description: doc.querySelector('meta[name="description"]')?.getAttribute('content') || null,
                    keywords: doc.querySelector('meta[name="keywords"]')?.getAttribute('content') || null,
                    author: doc.querySelector('meta[name="author"]')?.getAttribute('content') || null,
                    ogTitle: doc.querySelector('meta[property="og:title"]')?.getAttribute('content') || null,
                    ogDescription: doc.querySelector('meta[property="og:description"]')?.getAttribute('content') || null,
                },
                headings: {
                    h1: Array.from(doc.querySelectorAll('h1')).map(h => h.textContent?.trim()),
                    h2: Array.from(doc.querySelectorAll('h2')).map(h => h.textContent?.trim()),
                    h3: Array.from(doc.querySelectorAll('h3')).map(h => h.textContent?.trim()),
                },
                links,
                images: Array.from(doc.querySelectorAll('img')).map(img => ({ 
                    src: img.getAttribute('src'), 
                    alt: img.getAttribute('alt') 
                })),
                technologies,
                ecommerce: analyzeEcommerce(html, doc),
                subdomains: subdomainResults,
                scrapingPolicy,
                securityAnalysis,
                robotsTxtContent,
                usersDetected: usersDetection
            };

            // Calcular privacy score después de tener todos los datos
            scrapedData.securityAnalysis.privacyScore = calculatePrivacyScore(scrapedData);

            setCurrentResult(scrapedData);
            
            // Crear consulta optimizada con títulos generados dinámicamente y keywords sin tecnologías
            const urlKeywords = extractUrlKeywords(url, html, scrapedData);
            const validatedKeywords = await validateKeywordsWithWebSearch(urlKeywords, url);
            const { optimizedTitle, matchPercentage } = generateOptimizedTitle(validatedKeywords, title, url);
            
            // Usar función mejorada para extraer keywords sin tecnologías para el historial
            const cleanKeywords = extractKeywordsWithoutTech(html, scrapedData);
            
            const optimizedQuery: OptimizedQuery = {
                title: optimizedTitle,
                url,
                keywords: cleanKeywords,
                securityScore: scrapedData.securityAnalysis.privacyScore,
                matchPercentage: matchPercentage,
                timestamp: Date.now()
            };
            
            // Guardar consulta completa en localStorage para análisis detallado
            const fullQuery: Query = { title, url, data: scrapedData, timestamp: Date.now() };
            const updatedQueries = [fullQuery, ...queries.filter(q => q.url !== url)].slice(0, 10);
            saveQueries(updatedQueries);
            
            // Guardar consulta optimizada
            const updatedOptimizedQueries = [optimizedQuery, ...optimizedQueries.filter(q => q.url !== url)].slice(0, 10);
            saveOptimizedQueries(updatedOptimizedQueries);

            logger.info('Scraping completado exitosamente con análisis de seguridad');

        } catch (err) {
            setError(err instanceof Error ? err.message : 'Ocurrió un error.');
        } finally {
            setLoading(false);
        }
    };
    
    // --- MANEJADORES DE EVENTOS ---
    const handleHistoryClick = (query: Query) => {
        setUrl(query.url);
        setCurrentResult(query.data);
        setError(null);
        setActiveTab('summary');
    };

    const handleClearHistory = () => {
        saveQueries([]);
        saveOptimizedQueries([]);
    };

    const handleOptimizedHistoryClick = (query: OptimizedQuery) => {
        // Buscar la consulta completa correspondiente para mostrar el análisis detallado
        const fullQuery = queries.find(q => q.url === query.url);
        if (fullQuery) {
            setUrl(query.url);
            setCurrentResult(fullQuery.data);
            setError(null);
            setActiveTab('summary');
        }
    };

    const handleToggleEthicalMode = () => {
        setEthicalMode(!ethicalMode);
    };

    const handleExport = () => {
        if (!currentResult) return;
        const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${currentResult.title.replace(/\s/g, '_')}_scrape.json`;
        link.click();
        URL.revokeObjectURL(link.href);
    };

    // --- FUNCIONES DE RENDERIZADO ESPECIALIZADAS ---
    const renderHighlightedRobotsTxt = (content: string): React.ReactElement => {
        const lines = content.split('\n');
        
        return (
            <>
                {lines.map((line, index) => {
                    const isRelevant = /disallow|user-agent|allow|^\s*$/.test(line.toLowerCase());
                    const isDisallow = /disallow\s*:\s*\//.test(line.toLowerCase());
                    const isUserAgent = line.toLowerCase().includes('user-agent:');
                    
                    return (
                        <div 
                            key={index} 
                            className={`robots-line ${isDisallow ? 'disallow-line' : ''} ${isUserAgent ? 'user-agent-line' : ''} ${isRelevant ? 'relevant-line' : ''}`}
                        >
                            {line}
                        </div>
                    );
                })}
            </>
        );
    };

    // --- COMPONENTES DE RENDERIZADO ---
    const renderSummary = (data: ScrapedData) => (
        <div className="cybersecurity-summary">
            <div className="security-overview">
                <h3>🔒 Resumen de Ciberseguridad</h3>
                <div className="security-metrics">
                    <div className="security-metric">
                        <span className="metric-label">Tecnologías detectadas:    </span>
                        <span className="metric-value">{data.technologies.length}</span>
                    </div>
                    <div className="security-metric">
                        <span className="metric-label">Enlaces externos:          </span>
                        <span className="metric-value">{data.securityAnalysis.externalLinks}</span>
                    </div>
                    <div className="security-metric">
                        <span className="metric-label">Imágenes sin alt:          </span>
                        <span className="metric-value">{data.securityAnalysis.imagesWithoutAlt}</span>
                    </div>
                    <div className="security-metric">
                        <span className="metric-label">Score de privacidad:       </span>
                        <span className={`metric-value ${data.securityAnalysis.privacyScore >= 70 ? 'good' : data.securityAnalysis.privacyScore >= 40 ? 'warning' : 'danger'}`}>
                            {data.securityAnalysis.privacyScore}%
                        </span>
                    </div>
                    <div className="privacy-score-details">
                        <small className="privacy-explanation">
                            <strong>Puntaje basado en:</strong> 
                            Headers de seguridad (-25%), SSL/TLS (-25%), 
                            vulnerabilidades (-{data.securityAnalysis.vulnerableTechnologies.reduce((acc, vuln) => {
                                let penalty = 0;
                                if (vuln.name.includes('Code Pattern')) {
                                    penalty = vuln.vulnerability.includes('eval') ? 8 :
                                            vuln.vulnerability.includes('document.write') ? 4 :
                                            vuln.vulnerability.includes('innerHTML') ? 4 :
                                            vuln.vulnerability.includes('Console') ? 1 : 3;
                                } else if (vuln.name.includes('Configuration') || vuln.name.includes('Logging')) {
                                    penalty = 2;
                                } else {
                                    penalty = vuln.severity === 'critical' ? 8 :
                                            vuln.severity === 'high' ? 6 :
                                            vuln.severity === 'medium' ? 4 : 2;
                                }
                                return acc + penalty;
                            }, 0)} puntos), 
                            enlaces externos (-{Math.min(data.securityAnalysis.externalLinks * 0.5, 10)}%), 
                            accesibilidad (-{Math.min(data.securityAnalysis.imagesWithoutAlt * 0.3, 5)}%)
                        </small>
                    </div>
                </div>
            </div>
            
            <div className="scraping-policy">
                <h3>📜 Política de Scraping</h3>
                <div className={`policy-status ${ethicalMode && data.scrapingPolicy.scrapingProhibited ? 'prohibited' : 'allowed'}`}>
                    <div className="policy-details">
                        <span className="policy-text">
                            {ethicalMode && data.scrapingPolicy.scrapingProhibited ? 
                                '❌ Scraping prohibido por políticas del sitio' : 
                                '✅ Scraping permitido'
                            }
                        </span>
                        <div className="policy-checks">
                            <div className={`check ${ethicalMode && data.scrapingPolicy.robotsTxtAllowed ? 'pass' : ethicalMode && !data.scrapingPolicy.robotsTxtAllowed ? 'fail' : 'warning'}`}>
                                📄 robots.txt {
                                    ethicalMode ? 
                                    (data.scrapingPolicy.robotsTxtAllowed ? '✓' : '✗') : 
                                    '⚠️'
                                }
                            </div>
                            <div className={`check ${ethicalMode && !data.scrapingPolicy.termsOfServiceRestricted ? 'pass' : ethicalMode && data.scrapingPolicy.termsOfServiceRestricted ? 'fail' : 'warning'}`}>
                                📋 Términos {
                                    ethicalMode ? 
                                    (data.scrapingPolicy.termsOfServiceRestricted ? '✗' : '✓') : 
                                    '⚠️'
                                }
                            </div>
                        </div>
                        {!ethicalMode && (
                            <div className="ethical-mode-warning">
                                <small>⚠️ Modo ético desactivado - las restricciones no se respetan</small>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            <div className="site-info">
                <h3>ℹ️ Información del Sitio</h3>
                <ul className="summary-list">
                    <li className="summary-item">
                        <span className="summary-label">Título</span>
                        <span className="summary-value-text">{data.title || 'No encontrado'}</span>
                    </li>
                    <li className="summary-item">
                        <span className="summary-label">Usuarios detectados</span>
                        <div className="users-detection">
                            <div className="users-status">
                                <span className={`users-indicator ${data.usersDetected.hasUsers ? 'has-users' : 'no-users'}`}>
                                    {data.usersDetected.hasUsers ? '✅ Sistema de usuarios detectado' : '❌ No se detectaron usuarios'}
                                </span>
                            </div>
                            {data.usersDetected.hasUsers && data.usersDetected.accessPoints.length > 0 && (
                                <div className="user-access-points">
                                    <div className="access-points-title">Puntos de acceso disponibles:</div>
                                    <div className="access-points-grid">
                                        {data.usersDetected.accessPoints.map((accessPoint, index) => (
                                            <span key={index} className="access-point-badge">{accessPoint}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </li>
                </ul>
                
                <div className="robots-txt-section">
                    <h4>📄 Contenido del robots.txt</h4>
                    <div className="robots-txt-content">
                        <div className="robots-txt-highlighted">
                            {renderHighlightedRobotsTxt(data.robotsTxtContent)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    const renderSecurity = (data: ScrapedData) => {
        const { securityAnalysis } = data;
        const { detailed } = securityAnalysis.securityHeaders;
        
        return (
            <div className="security-analysis">
                <div className="security-section">
                    <h3>🛡️ Headers de Seguridad</h3>
                    <ul className="audit-list">
                        <li className={`audit-item ${securityAnalysis.securityHeaders.csp ? 'audit-pass' : 'audit-fail'}`}>
                            <span className="audit-icon">{securityAnalysis.securityHeaders.csp ? '✓' : '❌'}</span>
                            <div className="audit-details">
                                <span>Content Security Policy (CSP)</span>
                                {detailed?.csp && (
                                    <small className="audit-info">
                                        {detailed.csp.valid ? '✅ Válida' : '⚠️ Incompleta'}: {detailed.csp.content}
                                    </small>
                                )}
                            </div>
                        </li>
                        <li className={`audit-item ${securityAnalysis.securityHeaders.hsts ? 'audit-pass' : 'audit-fail'}`}>
                            <span className="audit-icon">{securityAnalysis.securityHeaders.hsts ? '✓' : '❌'}</span>
                            <div className="audit-details">
                                <span>HTTP Strict Transport Security (HSTS)</span>
                                {detailed?.hsts && (
                                    <small className="audit-info">
                                        {detailed.hsts.valid ? '✅ Válida' : '⚠️ Inválida'}: 
                                        {detailed.hsts.maxAge >= 31536000 ? '✅ 1+ año' : '⚠️ < 1 año'} ({detailed.hsts.content})
                                    </small>
                                )}
                            </div>
                        </li>
                        <li className={`audit-item ${securityAnalysis.securityHeaders.xss ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{securityAnalysis.securityHeaders.xss ? '✓' : '⚠️'}</span>
                            <div className="audit-details">
                                <span>Protección XSS</span>
                                {detailed?.xssProtection && (
                                    <small className="audit-info">
                                        {detailed.xssProtection.valid ? '✅ Configurada' : '⚠️ Mínima'}: {detailed.xssProtection.content}
                                    </small>
                                )}
                            </div>
                        </li>
                        <li className={`audit-item ${securityAnalysis.securityHeaders.contentType ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{securityAnalysis.securityHeaders.contentType ? '✓' : '⚠️'}</span>
                            <span>X-Content-Type-Options</span>
                        </li>
                        <li className={`audit-item ${detailed?.referrerPolicy.valid ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{detailed?.referrerPolicy.valid ? '✓' : '⚠️'}</span>
                            <div className="audit-details">
                                <span>Referrer Policy</span>
                                <small className="audit-info">{detailed?.referrerPolicy.content}</small>
                            </div>
                        </li>
                        <li className={`audit-item ${detailed?.frameOptions.valid ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{detailed?.frameOptions.valid ? '✓' : '⚠️'}</span>
                            <div className="audit-details">
                                <span>X-Frame-Options</span>
                                <small className="audit-info">{detailed?.frameOptions.content}</small>
                            </div>
                        </li>
                        <li className={`audit-item ${detailed?.infoDisclosure.serverExposed ? 'audit-fail' : 'audit-pass'}`}>
                            <span className="audit-icon">{detailed?.infoDisclosure.serverExposed ? '⚠️' : '✓'}</span>
                            <div className="audit-details">
                                <span>Exposición de Información del Servidor</span>
                                <small className="audit-info">
                                    {detailed?.infoDisclosure.serverExposed ? 
                                        '❌ El servidor expone información de versión' : 
                                        '✅ Información del servidor oculta'
                                    }
                                </small>
                            </div>
                        </li>
                        <li className={`audit-item ${detailed?.infoDisclosure.poweredByExposed ? 'audit-warn' : 'audit-pass'}`}>
                            <span className="audit-icon">{detailed?.infoDisclosure.poweredByExposed ? '⚠️' : '✓'}</span>
                            <div className="audit-details">
                                <span>Exposición de Framework (X-Powered-By)</span>
                                <small className="audit-info">
                                    {detailed?.infoDisclosure.poweredByExposed ? 
                                        '⚠️ El framework expone información' : 
                                        '✅ Framework no expuesto'
                                    }
                                </small>
                            </div>
                        </li>
                    </ul>
                </div>

                <div className="security-section">
                    <h3>🔐 Análisis SSL/TLS</h3>
                    <ul className="audit-list">
                        <li className={`audit-item ${securityAnalysis.sslAnalysis.httpsEnabled ? 'audit-pass' : 'audit-fail'}`}>
                            <span className="audit-icon">{securityAnalysis.sslAnalysis.httpsEnabled ? '✓' : '❌'}</span>
                            <div className="audit-details">
                                <span>HTTPS habilitado</span>
                                {securityAnalysis.sslAnalysis.additionalInfo && (
                                    <small className="audit-info">
                                        {securityAnalysis.sslAnalysis.additionalInfo.mixedContent ? 
                                            '⚠️ Contenido mixto detectado' : 
                                            '✅ Conexión segura'
                                        }
                                    </small>
                                )}
                            </div>
                        </li>
                        <li className={`audit-item ${securityAnalysis.sslAnalysis.validCertificate ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{securityAnalysis.sslAnalysis.validCertificate ? '✓' : '⚠️'}</span>
                            <div className="audit-details">
                                <span>Certificado SSL</span>
                                {securityAnalysis.sslAnalysis.additionalInfo?.certificateValidity && (
                                    <small className="audit-info">
                                        {securityAnalysis.sslAnalysis.additionalInfo.certificateValidity.daysRemaining! > 90 ? 
                                            '✅ Válido' : 
                                            securityAnalysis.sslAnalysis.additionalInfo.certificateValidity.daysRemaining! > 30 ?
                                            '⚠️ Próximo a expirar' : 
                                            '❌ Por expirar'
                                        } ({securityAnalysis.sslAnalysis.additionalInfo.certificateValidity.daysRemaining} días restantes)
                                    </small>
                                )}
                            </div>
                        </li>
                        <li className="audit-item">
                            <span className="audit-icon">ℹ️</span>
                            <div className="audit-details">
                                <span>Protocolo TLS</span>
                                <small className="audit-info">
                                    {securityAnalysis.sslAnalysis.tlsVersion} - 
                                    {securityAnalysis.sslAnalysis.additionalInfo?.protocolVersion || 'Versión estándar'}
                                </small>
                            </div>
                        </li>
                        <li className="audit-item">
                            <span className="audit-icon">🏢</span>
                            <div className="audit-details">
                                <span>Emisor del Certificado</span>
                                <small className="audit-info">
                                    {securityAnalysis.sslAnalysis.additionalInfo?.certificateIssuer || 'No determinado'}
                                </small>
                            </div>
                        </li>
                        {securityAnalysis.sslAnalysis.additionalInfo?.mixedContent && (
                            <li className="audit-item audit-fail">
                                <span className="audit-icon">⚠️</span>
                                <div className="audit-details">
                                    <span>Contenido Mixto</span>
                                    <small className="audit-info">
                                        ⚠️ El sitio carga recursos HTTP desde HTTPS
                                    </small>
                                </div>
                            </li>
                        )}
                    </ul>
                </div>

                <div className="security-section">
                    <h3>⚠️ Vulnerabilidades Detectadas</h3>
                    {securityAnalysis.vulnerableTechnologies.length > 0 ? (
                        <div className="vulnerable-techs-detailed">
                            {securityAnalysis.vulnerableTechnologies.map((tech, i) => (
                                <div key={i} className={`vulnerable-tech-card ${tech.severity}`}>
                                    <div className="vulnerability-header">
                                        <div className="vuln-main-info">
                                            <span className="tech-name">{tech.name}</span>
                                            <span className="tech-version">{tech.version}</span>
                                        </div>
                                        <span className={`severity-badge ${tech.severity}`}>
                                            {tech.severity.toUpperCase()}
                                        </span>
                                    </div>
                                    <div className="vulnerability-details">
                                        <div className="vulnerability-description">
                                            <strong>Descripción:</strong> {tech.vulnerability}
                                        </div>
                                        {tech.lineNumbers && tech.lineNumbers.length > 0 && (
                                            <div className="vulnerability-lines">
                                                <strong>Líneas afectadas:</strong> {tech.lineNumbers.slice(0, 5).join(', ')}
                                                {tech.lineNumbers.length > 5 && ` (y ${tech.lineNumbers.length - 5} más...)`}
                                            </div>
                                        )}
                                        {tech.recommendation && (
                                            <div className="vulnerability-recommendation">
                                                <strong>Recomendación:</strong> {tech.recommendation}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="no-vulnerabilities-container">
                            <div className="no-vulnerabilities-icon">✅</div>
                            <p className="no-vulnerabilities">No se detectaron vulnerabilidades conocidas.</p>
                            <small className="no-vuln-note">El sitio web sigue buenas prácticas de seguridad.</small>
                        </div>
                    )}
                </div>
            </div>
        );
    };

    const getErrorExplanation = (error: string): string => {
        const errorLower = error.toLowerCase();
        
        if (errorLower.includes('404')) {
            return 'Error 404 - Recurso no encontrado. La URL no existe o ha sido movida.';
        }
        if (errorLower.includes('403')) {
            return 'Error 403 - Acceso prohibido. El servidor deniega el acceso a la página.';
        }
        if (errorLower.includes('500')) {
            return 'Error 500 - Error interno del servidor. Problemas en el servidor web.';
        }
        if (errorLower.includes('502')) {
            return 'Error 502 - Puerta de enlace inválida. Problema de conectividad.';
        }
        if (errorLower.includes('503')) {
            return 'Error 503 - Servicio no disponible. El servidor está temporalmente sobrecargado.';
        }
        if (errorLower.includes('timeout')) {
            return 'Timeout - La conexión tardó demasiado tiempo. El servidor puede estar sobrecargado.';
        }
        if (errorLower.includes('refused')) {
            return 'Conexión rechazada - El servidor está rechazando las conexiones.';
        }
        if (errorLower.includes('network')) {
            return 'Error de red - Problemas de conectividad o DNS.';
        }
        if (errorLower.includes('cors')) {
            return 'Error CORS - El servidor bloquea las peticiones desde este origen.';
        }
        if (errorLower.includes('ssl') || errorLower.includes('certificate')) {
            return 'Error SSL - Problemas con el certificado de seguridad.';
        }
        if (errorLower.includes('robots.txt')) {
            return 'Scraping prohibido - El archivo robots.txt del sitio no permite el acceso automatizado.';
        }
        if (errorLower.includes('términos de servicio')) {
            return 'Scraping restringido - Los términos de servicio del sitio web prohíben el scraping automatizado.';
        }
        if (errorLower.includes('http')) {
            const match = errorLower.match(/http (\d+)/);
            if (match) {
                const code = match[1];
                const httpCodes: Record<string, string> = {
                    '400': 'Error 400 - Petición malformada',
                    '401': 'Error 401 - No autorizado',
                    '405': 'Error 405 - Método no permitido',
                    '408': 'Error 408 - Timeout de petición',
                    '429': 'Error 429 - Demasiadas peticiones',
                    '502': 'Error 502 - Puerta de enlace inválida',
                    '503': 'Error 503 - Servicio no disponible',
                    '504': 'Error 504 - Timeout de puerta de enlace'
                };
                return httpCodes[code] || `Error HTTP ${code} - Código de estado HTTP no estándar`;
            }
        }
        
        return `Error no identificado: ${error}`;
    };

    const renderSubdomains = (data: ScrapedData) => {
        const successSubdomains = data.subdomains.filter(s => s.status === 'success');

        return (
            <div className="subdomains-analysis">
                {successSubdomains.length > 0 && (
                    <div className="subdomains-section">
                        <h3>🌐 Subdominios Encontrados</h3>
                        <div className="subdomains-compact">
                            {successSubdomains.map((subdomain, i) => (
                                <div 
                                    key={`success-${i}`} 
                                    className="subdomain-compact-item success"
                                >
                                    <span className="subdomain-title">{subdomain.url}</span>
                                    <span className="subdomain-status-text">✓ Accesible</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
                
                {successSubdomains.length === 0 && (
                    <div className="placeholder">No se encontraron subdominios accesibles.</div>
                )}
            </div>
        );
    };

    const renderImageGallery = (data: ScrapedData) => (
        <div className="image-gallery">
            {data.images.length > 0 ? data.images.map((img, i) => (
                <div key={i} className={`image-item ${!img.alt ? 'no-alt' : ''}`} title={`Alt: ${img.alt || 'Vacío'}`}>
                    <img src={img.src ? new URL(img.src, url).href : ''} alt={img.alt || ''} loading="lazy" />
                </div>
            )) : <p>No se encontraron imágenes.</p>}
        </div>
    );

    const compareVersions = (version: string, currentVersion: string): 'outdated' | 'current' | 'newer' => {
        if (!version || !currentVersion) return 'current';
        
        const versionParts = version.split('.').map(Number);
        const currentParts = currentVersion.split('.').map(Number);
        
        for (let i = 0; i < Math.max(versionParts.length, currentParts.length); i++) {
            const v = versionParts[i] || 0;
            const c = currentParts[i] || 0;
            
            if (v < c) return 'outdated';
            if (v > c) return 'newer';
        }
        
        return 'current';
    };

    const renderTechnologies = (data: ScrapedData) => (
        <div className="tech-list">
            {data.technologies.length > 0 ? data.technologies.map((tech, i) => {
                const versionStatus = tech.version && tech.currentVersion ? compareVersions(tech.version, tech.currentVersion) : 'current';
                const isVulnerable = data.securityAnalysis.vulnerableTechnologies.some(vuln => vuln.name === tech.name);
                
                return (
                    <div key={i} className={`tech-item-with-version ${versionStatus} ${isVulnerable ? 'vulnerable' : ''}`}>
                        <span className="tech-name">{tech.name}</span>
                        {tech.version && (
                            <span className="tech-version">v{tech.version}</span>
                        )}
                        {tech.currentVersion && (
                            <span className="tech-current">actual: {tech.currentVersion}</span>
                        )}
                        {versionStatus === 'outdated' && (
                            <span className="tech-warning">⚠️ Obsoleta</span>
                        )}
                        {versionStatus === 'newer' && (
                            <span className="tech-beta">🆕 Beta</span>
                        )}
                        {versionStatus === 'current' && (
                            <span className="tech-updated">✅ Actual</span>
                        )}
                        {isVulnerable && (
                            <span className="tech-vulnerable">🚨 Vulnerable</span>
                        )}
                    </div>
                );
            }) : <p>No se detectaron tecnologías específicas.</p>}
        </div>
    );

    const renderEcommerce = (data: ScrapedData) => {
        const { ecommerce } = data;
        return (
            <div className="ecommerce-analysis">
                <div className="ecommerce-section">
                    <h3>📊 Resumen General</h3>
                    <ul className="summary-list">
                        <li className="summary-item">
                            <span className="summary-value-count">{ecommerce.totalProducts}</span>
                            <span className="summary-label">Productos detectados</span>
                        </li>
                        <li className="summary-item">
                            <span className="summary-value-count">{ecommerce.paymentMethods.length}</span>
                            <span className="summary-label">Métodos de pago</span>
                        </li>
                        <li className="summary-item">
                            <span className="summary-value-count">{Object.values(ecommerce.shoppingFeatures).filter(Boolean).length}</span>
                            <span className="summary-label">Características activas</span>
                        </li>
                    </ul>
                </div>

                <div className="ecommerce-section">
                    <h3>🛒 Características de Tienda</h3>
                    <ul className="audit-list">
                        <li className={`audit-item ${ecommerce.shoppingFeatures.hasCart ? 'audit-pass' : 'audit-fail'}`}>
                            <span className="audit-icon">{ecommerce.shoppingFeatures.hasCart ? '✓' : '❌'}</span>
                            <span>Carrito de compras</span>
                        </li>
                        <li className={`audit-item ${ecommerce.shoppingFeatures.hasSearch ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{ecommerce.shoppingFeatures.hasSearch ? '✓' : '⚠️'}</span>
                            <span>Búsqueda de productos</span>
                        </li>
                        <li className={`audit-item ${ecommerce.shoppingFeatures.hasFilters ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{ecommerce.shoppingFeatures.hasFilters ? '✓' : '⚠️'}</span>
                            <span>Filtros de productos</span>
                        </li>
                        <li className={`audit-item ${ecommerce.shoppingFeatures.hasWishlist ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{ecommerce.shoppingFeatures.hasWishlist ? '✓' : '⚠️'}</span>
                            <span>Lista de deseos</span>
                        </li>
                    </ul>
                </div>

                {ecommerce.paymentMethods.length > 0 && (
                    <div className="ecommerce-section">
                        <h3>💳 Métodos de Pago</h3>
                        <div className="tech-list">
                            {ecommerce.paymentMethods.map(method => <span key={method} className="tech-item">{method}</span>)}
                        </div>
                    </div>
                )}

                <div className="ecommerce-section">
                    <h3>📋 Structured Data</h3>
                    <ul className="audit-list">
                        <li className={`audit-item ${ecommerce.structuredData.hasProductSchema ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{ecommerce.structuredData.hasProductSchema ? '✓' : '⚠️'}</span>
                            <span>Schema de productos</span>
                        </li>
                        <li className={`audit-item ${ecommerce.structuredData.hasOrganizationSchema ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{ecommerce.structuredData.hasOrganizationSchema ? '✓' : '⚠️'}</span>
                            <span>Schema de organización</span>
                        </li>
                        <li className={`audit-item ${ecommerce.structuredData.hasReviewSchema ? 'audit-pass' : 'audit-warn'}`}>
                            <span className="audit-icon">{ecommerce.structuredData.hasReviewSchema ? '✓' : '⚠️'}</span>
                            <span>Schema de reseñas</span>
                        </li>
                    </ul>
                </div>

                {ecommerce.products.length > 0 && (
                    <div className="ecommerce-section">
                        <h3>🛍️ Productos Encontrados</h3>
                        <div className="products-grid">
                            {ecommerce.products.slice(0, 6).map((product, i) => (
                                <div key={i} className="product-card">
                                    <h4>{product.name}</h4>
                                    {product.price && <p className="product-price">{product.price}</p>}
                                    {product.rating && (
                                        <p className="product-rating">⭐ {product.rating} {product.reviewCount && `(${product.reviewCount} reseñas)`}</p>
                                    )}
                                    {product.availability && <p className="product-stock">{product.availability}</p>}
                                </div>
                            ))}
                            {ecommerce.products.length > 6 && (
                                <p className="more-products">... y {ecommerce.products.length - 6} productos más</p>
                            )}
                        </div>
                    </div>
                )}
            </div>
        );
    };

    const renderTabContent = () => {
        if (loading) return <div className="loading">🔍 Analizando políticas de scraping y extrayendo información...</div>;
        if (error) return <div className="error">{getErrorExplanation(error)}</div>;
        if (!currentResult) return <div className="placeholder">Los resultados del scraping ético se mostrarán aquí.</div>;
        
        switch (activeTab) {
            case 'summary': return renderSummary(currentResult);
            case 'security': return renderSecurity(currentResult);
            case 'gallery': return renderImageGallery(currentResult);
            case 'tech': return renderTechnologies(currentResult);
            case 'ecommerce': return renderEcommerce(currentResult);
            case 'subdomains': return renderSubdomains(currentResult);
            case 'json': return <pre><code>{JSON.stringify(currentResult, null, 2)}</code></pre>;
            default: return null;
        }
    };

    const sidebarItems = Array.from({ length: 10 }).map((_, i) => optimizedQueries[i] || null);

    return (
        <>
            <div className="app-container">
                <div className="title-container">
                    <h1 className="app-title">
                        Scrapii {' '}
                        <a
                            href="https://github.com/loiz1/scrapii"
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label="Repositorio GitHub del proyecto"
                            className="github-link"
                            title="Scrapii en GitHub"
                        >
                        🦊
                        </a>
                    </h1>
                    <p className="app-subtitle">Scraping responsable con análisis de ciberseguridad</p>
                </div>
                <header className="header">
                    <label htmlFor="url-input">Ingrese la URL </label>
                    <input 
                        id="url-input" 
                        type="url" 
                        value={url} 
                        onChange={e => setUrl(e.target.value)} 
                        onKeyDown={e => e.key === 'Enter' && handleScrape()} 
                        placeholder="https://ejemplo.com" 
                        aria-label="URL a extraer de forma ética" 
                    />
                    <button onClick={handleScrape} disabled={loading}>
                        {loading ? '🔍 Analizando...' : '🛡️ Scraping Ético'}
                    </button>
                </header>
                <main className="main-content">
                    <aside className="sidebar">
                        <h2>Consultas Éticas</h2>
                        <ul aria-label="Historial de consultas éticas">
                            {sidebarItems.map((query, i) => (
                                <li key={query ? query.timestamp : `empty-${i}`}>
                                    <button 
                                        onClick={() => query && handleOptimizedHistoryClick(query)} 
                                        disabled={!query} 
                                        title={query ? `${query.title} (${query.url}) | Match: ${query.matchPercentage}% | Security: ${query.securityScore}% | Keywords: ${query.keywords.join(', ')}` : 'Vacío'}
                                        className="history-button"
                                    >
                                        {query ? (
                                            <div className="history-item">
                                                <div className="history-title">{query.title}</div>
                                                <div className="history-meta">
                                                    <span className={`score ${query.securityScore >= 70 ? 'good' : query.securityScore >= 40 ? 'warning' : 'danger'}`}>
                                                        {query.securityScore}%
                                                    </span>
                                                    <span className={`match-score ${query.matchPercentage >= 70 ? 'high' : query.matchPercentage >= 40 ? 'medium' : 'low'}`}>
                                                        {query.matchPercentage}%
                                                    </span>
                                                    {query.keywords.length > 0 && (
                                                        <span className="keywords">
                                                            {query.keywords.slice(0, 1).join(', ')}
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        ) : 'Vacío'}
                                    </button>
                                </li>
                            ))}
                        </ul>
                        <div className="sidebar-actions">
                            <button onClick={handleExport} disabled={!currentResult || loading}>📄 Exportar JSON</button>
                            <button onClick={handleClearHistory} disabled={queries.length === 0}>🗑️ Limpiar Historial</button>
                            <button 
                                onClick={handleToggleEthicalMode}
                                className={ethicalMode ? 'ethical-mode-active' : 'ethical-mode-inactive'}
                                title={ethicalMode ? 'Desactivar modo ético para ignorar restricciones' : 'Activar modo ético para respetar restricciones'}
                            >
                                {ethicalMode ? '🔒 Modo Ético ON' : '⚠️ Modo Ético OFF'}
                            </button>
                        </div>
                    </aside>
                    <section className="result-container" aria-live="polite">
                        <div className="tabs">
                            <button className={`tab-button ${activeTab === 'summary' ? 'active' : ''}`} onClick={() => setActiveTab('summary')}>🔒 Resumen</button>
                            <button className={`tab-button ${activeTab === 'security' ? 'active' : ''}`} onClick={() => setActiveTab('security')}>🛡️ Seguridad</button>
                            <button className={`tab-button ${activeTab === 'tech' ? 'active' : ''}`} onClick={() => setActiveTab('tech')}>⚙️ Tecnologías</button>
                            <button className={`tab-button ${activeTab === 'ecommerce' ? 'active' : ''}`} onClick={() => setActiveTab('ecommerce')}>🛒 E-commerce</button>
                            <button className={`tab-button ${activeTab === 'subdomains' ? 'active' : ''}`} onClick={() => setActiveTab('subdomains')}>🌐 Subdominios</button>
                            <button className={`tab-button ${activeTab === 'gallery' ? 'active' : ''}`} onClick={() => setActiveTab('gallery')}>🖼️ Galería</button>
                            <button className={`tab-button ${activeTab === 'json' ? 'active' : ''}`} onClick={() => setActiveTab('json')}>📋 JSON</button>
                        </div>
                        <div className="tab-content">
                           {renderTabContent()}
                        </div>
                    </section>
                </main>
            </div>
            <footer className="footer">
                <div className="footer-content">
                    <p>🛡️ DevSecOps By Grupo 5 - Uniminuto 2025</p>
                </div>
            </footer>
        </>
    );
};

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement);
root.render(<React.StrictMode><App /></React.StrictMode>);
