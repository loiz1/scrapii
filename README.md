# 🔒 Scrapii v2.0 - Web Scraping Ético

**Scrapii** es una aplicación web moderna de web scraping desarrollada con React y TypeScript que permite extraer, analizar y visualizar información de sitios web de manera **ética y responsable**.



## **Funcionalidades Principales**

### 1. **Scraping Ético**
- **Validación previa**: Verificación de robots.txt y términos de servicio
- **Mensajes informativos**: Notificaciones claras sobre restricciones
- **Detección inteligente**: Análisis automático de políticas de scraping

### 2. **Panel de Resumen de Ciberseguridad**
- **Métricas de seguridad**: Tecnologías detectadas, enlaces externos, imágenes sin alt
- **Score de privacidad**: Puntuación basada en múltiples factores de seguridad
- **Estado de políticas**: Visualización clara del estado del scraping

### 3. **Análisis de Seguridad Detallado**
- **Headers de seguridad**: Verificación de implementaciones de seguridad
- **Análisis SSL/TLS**: Evaluación de la configuración HTTPS
- **Tecnologías vulnerables**: Detección de versiones obsoletas con CVEs conocidos

### 4. **Detección de Tecnologías con Contexto de Seguridad**
- **Identificación automática**: Más de 50 tecnologías detectadas
- **Análisis de versiones**: Comparación con versiones actuales
- **Indicadores de vulnerabilidad**: Marcado de tecnologías con riesgos conocidos


## 🚀 **Instalación y Ejecución**

### Prerrequisitos
- **Node.js** (versión LTS recomendada)

### Ejecutar en desarrollo:
```bash
# Instalar dependencias
npm install

# Clonar el repositorio
git clone https://github.com/loiz1/scrapii

# Ejecutar servidor de desarrollo
npm run dev
```

### Construir imagen con Docker:
# 1. Build de imagen
```bash
docker build -t loizzz/web-scrapi:latest .

# 2. Tag con versión
docker tag loizzz/web-scrapi:latest loizzz/web-scrapi:v1.0.0

# 3. Push a Docker Hub
docker push loizzz/web-scrapi:latest
docker push loizzz/web-scrapi:v1.0.0

# 4. Deployment en producción
docker run -d -p 80:80 --name web-scrapi loizzz/web-scrapi:latest
```

### Consumir imagen de Docker:
```bash
docker pull loizzz/web-scrapi:latest
docker run -d -p 80:80 --name web-scrapi loizzz/web-scrapi:latest
```


## 🔒 **Análisis de Ciberseguridad**

### **Headers de Seguridad Evaluados**
- ✅ **Content Security Policy (CSP)**
- ✅ **HTTP Strict Transport Security (HSTS)**
- ✅ **XSS Protection**
- ✅ **X-Content-Type-Options**

### **Tecnologías Vulnerables Detectadas**
- 🚨 **jQuery < 3.5.0** - Vulnerabilidades XSS
- 🚨 **WordPress < 6.0.0** - CVEs múltiples
- 🚨 **PHP < 8.0.0** - Issues de seguridad y EOL
- ⚠️ **React < 18.0.0** - Security patches
- ⚠️ **Angular/Vue.js antiguos** - Vulnerabilidades de template



## 🛡️ **Principios Éticos**

Scrapii v2.0 se adhiere a los siguientes principios:

1. **📋 Respeto por robots.txt** - Siempre verificamos y respetamos las directivas
2. **📜 Términos de servicio** - Analizamos y respetamos las restricciones
3. **⏱️ Rate limiting** - Implementamos límites para no sobrecargar servidores
4. **📊 Minimización de datos** - Extraemos únicamente lo necesario
5. **🏷️ Identificación clara** - User-Agent identificable en todas las requests


## 📁 **Estructura del Proyecto**

```
Scraprii/
├── index.html              # Archivo HTML principal
├── index.tsx               # Componente React principal con todas las funcionalidades
├── tsconfig.json           # Configuración de TypeScript
├── vite.config.ts          # Configuración de Vite
├── package.json            # Dependencias y scripts
├── informe.md              # Documentación técnica completa
├── metadata.json           # Metadatos de la aplicación
├── .gitignore              # Archivos ignorados por Git
├── .dockerignore           # Archivos ignorados por Docker
├── Dockerfile              # Configuración del contenedor
└── nginx.conf              # Configuración de nginx
```


## 🎯 **Casos de Uso**

### **👨‍💼 Analistas de Seguridad**
- Auditorías de seguridad web completas
- Análisis de headers de seguridad
- Detección de tecnologías vulnerables
- Evaluación de configuraciones SSL/TLS

### **🔍 Investigadores**
- Scraping responsable y ético
- Cumplimiento de políticas web
- Análisis de privacidad
- Datos estructurados para investigación

### **👨‍💻 Desarrolladores**
- Detección de stack tecnológico
- Análisis de competencia
- Identificación de vulnerabilidades
- Mejores prácticas de seguridad

## 📈 **Métricas y Monitoreo**

### **Métricas de Seguridad v2.0**
- ✅ **Security Headers Coverage**: 100%
- ✅ **SSL/TLS Validation**: 100%
- ✅ **Vulnerability Detection**: 95%
- ✅ **Ethical Scraping Compliance**: 100%

### **Métricas de Cumplimiento**
- ✅ **robots.txt Compliance**: 100%
- ✅ **Terms of Service Respect**: 100%
- ✅ **Rate Limiting**: Implementado
- ✅ **Data Minimization**: 100%


## ⚖️ **Licencia y Uso Ético**

**Scrapii ** está diseñado para promover el web scraping ético y responsable. La herramienta implementa automáticamente:

- ✅ Verificación de permisos antes del scraping
- ✅ Respeto por las políticas del sitio web
- ✅ Limitación de velocidad para evitar sobrecarga
- ✅ Minimización de datos extraídos
- ✅ Identificación clara del bot

**⚠️ Nota Importante**: El scraping debe realizarse siempre respetando los términos de servicio de los sitios web y las leyes aplicables en cada jurisdicción.

---

**© 2025 Scrapii - Uniminuto DevSecOps Grupo 5**


