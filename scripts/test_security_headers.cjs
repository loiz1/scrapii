#!/usr/bin/env node

/**
 * Script de prueba para verificar headers de seguridad
 * Uso: node scripts/test_security_headers.cjs [url]
 */

const http = require('http');
const https = require('https');

const DEFAULT_URL = process.argv[2] || 'http://localhost:5173';

// Headers de seguridad que esperamos encontrar
const EXPECTED_HEADERS = {
  'Content-Security-Policy': {
    critical: true,
    description: 'Prevención de XSS'
  },
  'Strict-Transport-Security': {
    critical: true,
    description: 'Prevención de ataques man-in-the-middle'
  },
  'X-Content-Type-Options': {
    critical: true,
    description: 'Prevención de MIME sniffing'
  },
  'X-Frame-Options': {
    critical: false,
    description: 'Prevención de clickjacking'
  },
  'Referrer-Policy': {
    critical: false,
    description: 'Control de información de referrer'
  },
  'Permissions-Policy': {
    critical: false,
    description: 'Control de características del navegador'
  }
};

// Headers que NO deberían estar presentes (exposición de información)
const UNWANTED_HEADERS = [
  'Server',
  'X-Powered-By',
  'X-AspNet-Version',
  'X-AspNetMvc-Version'
];

function makeRequest(url) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname || '/',
      method: 'HEAD',
      headers: {
        'User-Agent': 'Security-Headers-Test/1.0'
      }
    };
    
    const req = protocol.request(options, (res) => {
      resolve({
        statusCode: res.statusCode,
        headers: res.headers
      });
    });
    
    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    req.end();
  });
}

function validateHeader(headerName, headerValue) {
  const validation = EXPECTED_HEADERS[headerName];
  if (!validation) return null;
  
  const isPresent = !!headerValue;
  const isValid = isPresent && headerValue.length > 0;
  
  return {
    name: headerName,
    present: isPresent,
    valid: isValid,
    value: headerValue || '',
    critical: validation.critical,
    description: validation.description,
    score: isValid ? (validation.critical ? 25 : 10) : 0
  };
}

function checkUnwantedHeaders(headers) {
  const found = [];
  UNWANTED_HEADERS.forEach(header => {
    if (headers[header.toLowerCase()]) {
      found.push({
        name: header,
        value: headers[header.toLowerCase()],
        severity: 'WARNING'
      });
    }
  });
  return found;
}

function generateReport(results, unwanted, url) {
  let report = `# 🔒 Reporte de Headers de Seguridad\n\n`;
  report += `**URL analizada**: ${url}\n`;
  report += `**Fecha**: ${new Date().toISOString()}\n\n`;
  
  // Estado general
  const criticalHeaders = results.filter(r => r.critical && r.present);
  const criticalMissing = results.filter(r => r.critical && !r.present);
  const optionalHeaders = results.filter(r => !r.critical && r.present);
  const optionalMissing = results.filter(r => !r.critical && !r.present);
  
  report += `## 📊 Resumen\n\n`;
  report += `- **Headers críticos presentes**: ${criticalHeaders.length}/${criticalHeaders.length + criticalMissing.length}\n`;
  report += `- **Headers opcionales presentes**: ${optionalHeaders.length}/${optionalHeaders.length + optionalMissing.length}\n`;
  report += `- **Score estimado**: ${results.reduce((sum, r) => sum + r.score, 0)}/100\n\n`;
  
  // Headers críticos
  if (criticalHeaders.length > 0 || criticalMissing.length > 0) {
    report += `## 🚨 Headers Críticos\n\n`;
    
    criticalHeaders.forEach(header => {
      report += `✅ **${header.name}**\n`;
      report += `- **Estado**: Presente\n`;
      report += `- **Valor**: \`${header.value}\`\n`;
      report += `- **Descripción**: ${header.description}\n\n`;
    });
    
    criticalMissing.forEach(header => {
      report += `❌ **${header.name}**\n`;
      report += `- **Estado**: Faltante\n`;
      report += `- **Descripción**: ${header.description}\n`;
      report += `- **Impacto**: Crítico para seguridad\n\n`;
    });
  }
  
  // Headers opcionales
  if (optionalHeaders.length > 0 || optionalMissing.length > 0) {
    report += `## ℹ️ Headers Opcionales\n\n`;
    
    optionalHeaders.forEach(header => {
      report += `✅ **${header.name}**\n`;
      report += `- **Estado**: Presente\n`;
      report += `- **Valor**: \`${header.value}\`\n`;
      report += `- **Descripción**: ${header.description}\n\n`;
    });
    
    optionalMissing.forEach(header => {
      report += `⚠️ **${header.name}**\n`;
      report += `- **Estado**: Faltante\n`;
      report += `- **Descripción**: ${header.description}\n`;
      report += `- **Impacto**: Recomendado para mejor seguridad\n\n`;
    });
  }
  
  // Headers no deseados
  if (unwanted.length > 0) {
    report += `## ⚠️ Headers de Exposición Detectados\n\n`;
    unwanted.forEach(header => {
      report += `🚨 **${header.name}**: \`${header.value}\`\n`;
      report += `- **Problema**: Expone información del servidor\n`;
      report += `- **Recomendación**: Remover este header\n\n`;
    });
  } else {
    report += `## ✅ Configuración de Exposición\n\n`;
    report += `✅ **No se detectaron headers de exposición**\n`;
    report += `- Información del servidor correctamente oculta\n\n`;
  }
  
  // Recomendaciones
  report += `## 🎯 Recomendaciones\n\n`;
  
  if (criticalMissing.length > 0) {
    report += `### Prioridad Alta - Implementar inmediatamente:\n`;
    criticalMissing.forEach(header => {
      report += `- ${header.name}\n`;
    });
    report += `\n`;
  }
  
  if (optionalMissing.length > 0) {
    report += `### Prioridad Media - Implementar si es posible:\n`;
    optionalMissing.forEach(header => {
      report += `- ${header.name}\n`;
    });
    report += `\n`;
  }
  
  if (unwanted.length > 0) {
    report += `### Headers a Remover:\n`;
    unwanted.forEach(header => {
      report += `- ${header.name}\n`;
    });
    report += `\n`;
  }
  
  // Score final
  const totalScore = results.reduce((sum, r) => sum + r.score, 0);
  const maxScore = Object.keys(EXPECTED_HEADERS).length * 25; // Asumiendo 25pts por header crítico
  const percentage = Math.round((totalScore / maxScore) * 100);
  
  let grade = 'F';
  let status = 'Crítico';
  
  if (percentage >= 90) { grade = 'A+'; status = 'Excelente'; }
  else if (percentage >= 80) { grade = 'A'; status = 'Muy Bueno'; }
  else if (percentage >= 70) { grade = 'B'; status = 'Bueno'; }
  else if (percentage >= 60) { grade = 'C'; status = 'Aceptable'; }
  else if (percentage >= 50) { grade = 'D'; status = 'Insuficiente'; }
  
  report += `## 🏆 Calificación Final\n\n`;
  report += `- **Score**: ${totalScore}/${maxScore} (${percentage}%)\n`;
  report += `- **Calificación**: ${grade}\n`;
  report += `- **Estado**: ${status}\n\n`;
  
  if (percentage < 80) {
    report += `**⚠️ Se recomienda implementar los headers faltantes para mejorar la seguridad.**\n\n`;
  } else {
    report += `✅ **Excelente configuración de headers de seguridad.**\n\n`;
  }
  
  return report;
}

async function main() {
  try {
    console.log(`🔍 Analizando headers de seguridad para: ${DEFAULT_URL}`);
    console.log('⏳ Realizando solicitud...\n');
    
    const result = await makeRequest(DEFAULT_URL);
    
    if (result.statusCode >= 400) {
      throw new Error(`HTTP ${result.statusCode}: Server responded with error`);
    }
    
    // Validar headers esperados
    const validatedHeaders = Object.keys(EXPECTED_HEADERS).map(headerName => {
      const headerValue = result.headers[headerName.toLowerCase()];
      return validateHeader(headerName, headerValue);
    }).filter(Boolean);
    
    // Verificar headers no deseados
    const unwantedHeaders = checkUnwantedHeaders(result.headers);
    
    // Generar y mostrar reporte
    const report = generateReport(validatedHeaders, unwantedHeaders, DEFAULT_URL);
    console.log(report);
    
    // Guardar reporte en archivo
    const fs = require('fs');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `security-headers-report-${timestamp}.md`;
    
    fs.writeFileSync(filename, report);
    console.log(`📄 Reporte guardado en: ${filename}`);
    
    // Exit code basado en score
    const score = validatedHeaders.reduce((sum, r) => sum + r.score, 0);
    const maxScore = Object.keys(EXPECTED_HEADERS).length * 25;
    const percentage = (score / maxScore) * 100;
    
    if (percentage < 70) {
      process.exit(1); // Headers de seguridad insuficientes
    } else {
      process.exit(0); // Headers de seguridad aceptables
    }
    
  } catch (error) {
    console.error('❌ Error durante el análisis:', error.message);
    process.exit(1);
  }
}

// Ejecutar si se llama directamente
if (require.main === module) {
  main();
}

module.exports = { makeRequest, validateHeader, generateReport };