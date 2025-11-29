# 🚀 Guía de Implementación de Headers de Seguridad

*Integración rápida en proyecto Scrapii*

---

## 📋 Resumen de Archivos Creados

1. **`docs/headers_seguridad_organizados.md`** - Documentación completa del análisis
2. **`src/utils/security_headers_generator.ts`** - Generador de headers reutilizable
3. **`src/utils/vite_security_config.ts`** - Configuración específica para Vite

---

## 🔧 Implementación en Vite

### Opción 1: Integración Directa en vite.config.ts

```typescript
import { defineConfig } from 'vite';
import { getViteConfigHeaders } from './src/utils/vite_security_config';

export default defineConfig(({ mode }) => {
  const isDevelopment = mode === 'development';
  const headers = getViteConfigHeaders(isDevelopment);
  
  return {
    server: {
      headers: isDevelopment ? undefined : headers
    },
    preview: {
      headers
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ['react', 'react-dom'],
          },
        },
      },
      minify: 'terser',
      terserOptions: {
        compress: {
          drop_console: true,
          drop_debugger: true,
        },
      },
    },
  };
});
```

### Opción 2: Usando la función helper (Recomendado)

```typescript
import { defineConfig } from 'vite';
import { setupSecurityHeaders } from './src/utils/vite_security_config';

export default defineConfig(({ mode }) => {
  const isDevelopment = mode === 'development';
  
  return {
    ...setupSecurityHeaders(isDevelopment),
    // ... otras configuraciones existentes
  };
});
```

---

## 🧪 Verificación de Implementación

### 1. Verificar headers en desarrollo:
```bash
# Iniciar servidor de desarrollo
npm run dev

# Verificar headers (en otra terminal)
curl -I http://localhost:5173
```

### 2. Verificar headers en producción:
```bash
# Construir proyecto
npm run build

# Iniciar servidor de vista previa
npm run preview

# Verificar headers
curl -I http://localhost:4173
```

### 3. Usar herramientas de verificación:
- [securityheaders.com](https://securityheaders.com)
- [observatory.mozilla.org](https://observatory.mozilla.org)
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com)

---

## 📊 Testing y Validación

### Test básico de headers
```bash
# Script para verificar todos los headers importantes
curl -s -I http://localhost:5173 | grep -E "(Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options|Referrer-Policy)"
```

### Test de CSP con herramientas online
1. Ir a [CSP Evaluator](https://csp-evaluator.withgoogle.com)
2. Ingresar tu URL o probar políticas localmente
3. Verificar que no hay inline scripts no autorizados

---

## ⚙️ Configuraciones por Entorno

### Desarrollo (Permisivo)
```typescript
const devHeaders = {
  'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
  'Strict-Transport-Security': 'max-age=0', // Deshabilitado
  'X-Frame-Options': 'SAMEORIGIN', // Más permisivo
  // ...
};
```

### Producción (Estricto)
```typescript
const prodHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' https://corsproxy.io; ...",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  // ...
};
```

---

## 🛠️ Solución de Problemas Comunes

### 1. Error: CSP bloquea scripts legítimos
**Problema**: Scripts necesarios están siendo bloqueados por CSP
**Solución**: 
```typescript
// Agregar fuentes necesarias a CSP
const csp = [
  "script-src 'self' 'unsafe-inline' https://corsproxy.io",
  // Agregar más fuentes según necesites
].join('; ');
```

### 2. Error: HSTS no se aplica
**Problema**: Header HSTS no aparece o es ignorado
**Solución**:
- Verificar que HTTPS está funcionando
- HSTS solo funciona con HTTPS
- Probar con `max-age=31536000; includeSubDomains`

### 3. Error: X-Frame-Options rompe iframes legítimos
**Problema**: Sitio no puede ser embebido donde debería
**Solución**:
```typescript
// Para sitios que deben ser embebidos
'X-Frame-Options': 'SAMEORIGIN'

// Para sitios standalone (recomendado)
'X-Frame-Options': 'DENY'
```

### 4. Warning: Headers no se aplican en development
**Problema**: Headers no aparecen en modo desarrollo
**Solución**:
```typescript
// En vite.config.ts
server: {
  headers: headers // Aplicar también en development si es necesario
}
```

---

## 📈 Monitoreo Continuo

### 1. Verificación automática en CI/CD
```yaml
# .github/workflows/security.yml
- name: Verify Security Headers
  run: |
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" https://tu-dominio.com)
    HEADERS=$(curl -s -I https://tu-dominio.com)
    
    if echo "$HEADERS" | grep -q "Content-Security-Policy"; then
      echo "✅ CSP header present"
    else
      echo "❌ CSP header missing"
      exit 1
    fi
```

### 2. Alertas de configuración
```typescript
// Agregar al inicio de la aplicación
if (process.env.NODE_ENV === 'production') {
  fetch('/health-check')
    .then(response => {
      if (!response.headers.get('Content-Security-Policy')) {
        console.warn('⚠️ CSP header missing in production!');
      }
    });
}
```

---

## 📋 Checklist de Implementación

### Pre-implementación
- [ ] Revisar CSP actual y identificar fuentes necesarias
- [ ] Verificar configuración HTTPS para HSTS
- [ ] Identificar si el sitio necesita ser embebido (X-Frame-Options)
- [ ] Revisar dependencias de analytics que puedan necesitar Referrer-Policy

### Implementación
- [ ] Integrar configuración en vite.config.ts
- [ ] Aplicar headers en development para testing
- [ ] Aplicar headers estrictos en production
- [ ] Probar funcionalidades críticas con CSP

### Post-implementación
- [ ] Verificar score en securityheaders.com
- [ ] Testear en múltiples navegadores
- [ ] Monitorear errores CSP en consola
- [ ] Configurar alertas en CI/CD

### Validación final
- [ ] Score A o A+ en securityheaders.com
- [ ] No hay errores CSP en consola de navegadores
- [ ] Funcionalidades críticas funcionan correctamente
- [ ] Headers aplicados consistentemente en todos los endpoints

---

## 📞 Recursos Adicionales

- [MDN Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Security Headers Scanner](https://securityheaders.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

*Guía actualizada: 2025-11-29*  
*Proyecto: Scrapii Security Implementation*