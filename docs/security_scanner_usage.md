# 🔒 Guía de Uso del Scanner de Seguridad Mejorado

## Descripción
Sistema de detección de vulnerabilidades con técnicas anti-falsos-positivos, diseñado para eliminar alertas incorrectas manteniendo alta precisión en la detección de amenazas reales.

## Instalación y Configuración

### Prerrequisitos
- Node.js 16+
- Proyecto TypeScript/JavaScript

### Archivos Principales
```
src/utils/security_scanner.ts     # Scanner principal mejorado
scripts/security_scan_improved.js # CLI para ejecutar escaneos
scripts/test_false_positive_detection.cjs # Pruebas comparativas
docs/security_scanner_usage.md   # Esta guía
```

## Uso

### Ejecutar Escaneo Completo
```bash
node scripts/security_scan_improved.js ../tu-proyecto
```

### Ejecutar Pruebas de Falsos Positivos
```bash
node scripts/test_false_positive_detection.cjs
```

### Uso Programático
```typescript
import { EnhancedSecurityScanner } from '../src/utils/security_scanner.ts';

const scanner = new EnhancedSecurityScanner();

// Escanear un archivo individual
const vulnerabilities = scanner.scanFile('src/app.ts');
console.log('Vulnerabilidades:', vulnerabilities);

// Escanear proyecto completo
const results = scanner.scanProject('/ruta/a/proyecto');
console.log('Resumen:', results.summary);

// Generar reporte
const report = scanner.generateReport(results);
console.log(report);
```

## Características Principales

### ✅ Whitelists Inteligentes
- **Google APIs**: GTM, Analytics, Maps, Site Verification
- **Servicios CDN**: unpkg, jsdelivr, cdnjs
- **APIs públicas**: OpenAI, Anthropic, Gemini

### ✅ Análisis Contextual
- Análisis de 3 líneas de contexto por línea escaneada
- Detección de entrada de usuario sin sanitizar
- Validación semántica de usos seguros

### ✅ Sistema de Confianza
- **Alta confianza (≥95%)**: Reportar automáticamente
- **Confianza media (75-94%)**: Análisis adicional
- **Confianza baja (<75%)**: Filtrar como falsos positivos

### ✅ Patrones de Exclusión
- Comentarios de código
- Placeholders y ejemplos
- Variables de entorno
- Contenido hardcodeado seguro

## Configuración Avanzada

### Personalizar Whitelists
```typescript
const scanner = new EnhancedSecurityScanner();

// Agregar nuevas APIs a la whitelist
scanner.apiKeyWhitelist.add('tu-api-pattern');

// Modificar patrones de exclusión
scanner.patterns[0].exclusions.push(/mi-patron/i);
```

### Ajustar Umbrales de Confianza
```typescript
// Modificar umbral mínimo de confianza
const results = scanner.scanProject(projectPath)
    .filter(vuln => vuln.confidence >= 0.85); // Solo alertas muy seguras
```

### Agregar Nuevos Patrones
```typescript
const customPattern = {
  id: 'MI_VULNERABILIDAD',
  name: 'Mi Vulnerabilidad Personalizada',
  severity: 'HIGH',
  patterns: [/mi-patron/g],
  contexts: ['assignment'],
  exclusions: [/comentario/i],
  confidence: 0.90
};

scanner.patterns.push(customPattern);
```

## Interpretación de Resultados

### Estructura de Vulnerabilidades
```typescript
interface FoundVulnerability {
  id: string;                    // ID del patrón
  name: string;                  // Nombre descriptivo
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  line: number;                  // Línea donde se encontró
  context: string;               // Contexto (3 líneas)
  snippet: string;               // Código específico
  confidence: number;            // 0-1, nivel de confianza
  isFalsePositive: boolean;      // Si es falso positivo
  reason: string;                // Razón de clasificación
}
```

### Niveles de Severidad
- **CRITICAL**: API keys, credenciales, vulnerabilidades de inyección
- **HIGH**: XSS, eval, setTimeout/setInterval con variables
- **MEDIUM**: Uso inseguro de funciones, patrones de riesgo
- **LOW**: Advertencias menores, mejores prácticas

## Mejores Prácticas

### Para Desarrolladores
1. **Evitar patrones problemáticos**:
   - No hardcodear API keys reales
   - Sanitizar entrada de usuario antes de innerHTML
   - Usar comentarios explicativos en usos seguros

2. **Configurar apropiadamente**:
   - Agregar whitelists para APIs conocidas
   - Documentar contextos seguros con comentarios
   - Revisar umbrales de confianza

### Para CI/CD
```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    node scripts/security_scan_improved.js .
    if [ $? -eq 0 ]; then
      echo "✅ Security scan passed"
    else
      echo "❌ Security vulnerabilities found"
      exit 1
    fi
```

## Solución de Problemas

### Falsos Positivos Persistentes
1. Verificar whitelists para servicios conocidos
2. Agregar comentarios explicativos en código seguro
3. Ajustar patrones de exclusión
4. Personalizar umbrales de confianza

### Vulnerabilidades Reales No Detectadas
1. Revisar patrones existentes en `security_scanner.ts`
2. Agregar nuevos patrones específicos para tu proyecto
3. Ajustar contexto de análisis
4. Verificar formato de archivos soportados (.ts, .tsx, .js, .jsx, .html)

### Errores de Ejecución
- Verificar que Node.js sea versión 16+
- Asegurar permisos de lectura en archivos del proyecto
- Revisar que las rutas de archivos sean correctas

## Integración con Herramientas

### ESLint
```json
{
  "extends": ["./custom-security-rules.json"]
}
```

### Git Hooks
```bash
# .git/hooks/pre-commit
node scripts/security_scan_improved.js .
if [ $? -ne 0 ]; then
  echo "Security scan failed. Commit aborted."
  exit 1
fi
```

### IDE Extensions
El scanner puede integrarse con:
- VS Code extensions
- JetBrains IDE plugins  
- Sublime Text packages

## Actualizaciones y Mantenimiento

### Actualizar Whitelists
```bash
# Mantener listas actualizadas de servicios conocidos
npm run update-security-whitelists
```

### Actualizar Patrones
```bash
# Actualizar base de datos de vulnerabilidades conocidas
npm run update-security-patterns
```

### Generar Reportes Automáticos
```bash
# Generar reportes programáticos
node scripts/generate_security_reports.js --format=json --output=security-report.json
```

## Soporte y Contribuciones

### Reportar Falsos Positivos
Crear issue con:
1. Código que genera falso positivo
2. Contexto de uso seguro
3. Patrón que debería ser whitelisted
4. Versión del scanner

### Contribuir Patrones
1. Fork del repositorio
2. Agregar patrón en `security_scanner.ts`
3. Agregar prueba en `test_false_positive_detection.cjs`
4. Crear pull request con documentación

---

*Última actualización: 2025-11-28*