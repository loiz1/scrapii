#!/usr/bin/env node

/**
 * CLI para el Scanner de Seguridad Mejorado
 * Ejecuta el análisis con técnicas anti-falsos-positivos
 */

const { EnhancedSecurityScanner } = require('../src/utils/security_scanner.ts');
const path = require('path');

function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Uso: node scripts/security_scan_improved.js [ruta-del-proyecto]');
        console.log('Ejemplo: node scripts/security_scan_improved.js ../');
        process.exit(1);
    }

    const projectPath = args[0];
    const scanner = new EnhancedSecurityScanner();

    console.log('🔍 Iniciando análisis de seguridad mejorado...');
    console.log('📁 Proyecto:', projectPath);
    console.log('⏱️ Fecha:', new Date().toISOString());
    console.log('=' .repeat(50));

    try {
        const results = scanner.scanProject(projectPath);
        
        // Mostrar resumen
        console.log('\n📊 RESUMEN:');
        console.log(`   Archivos analizados: ${results.files}`);
        console.log(`   Falsos positivos filtrados: ${results.falsePositives}`);
        console.log(`   Vulnerabilidades reales: ${results.vulnerabilities.length}`);
        
        if (Object.keys(results.summary).length > 0) {
            console.log('\n📈 POR SEVERIDAD:');
            for (const [severity, count] of Object.entries(results.summary)) {
                const emoji = severity === 'CRITICAL' ? '🚨' : 
                             severity === 'HIGH' ? '⚠️' : 
                             severity === 'MEDIUM' ? '⚡' : 'ℹ️';
                console.log(`   ${emoji} ${severity}: ${count}`);
            }
        }

        // Mostrar vulnerabilidades
        if (results.vulnerabilities.length > 0) {
            console.log('\n🚨 VULNERABILIDADES DETECTADAS:');
            console.log('=' .repeat(50));
            
            // Agrupar por severidad
            const bySeverity = {};
            results.vulnerabilities.forEach(vuln => {
                if (!bySeverity[vuln.severity]) {
                    bySeverity[vuln.severity] = [];
                }
                bySeverity[vuln.severity].push(vuln);
            });

            for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
                const vulns = bySeverity[severity];
                if (!vulns || vulns.length === 0) continue;

                console.log(`\n${severity} (${vulns.length} casos):`);
                console.log('-'.repeat(30));
                
                vulns.forEach(vuln => {
                    console.log(`  📍 Línea ${vuln.line}: ${vuln.name}`);
                    console.log(`     🔍 "${vuln.snippet.substring(0, 80)}..."`);
                    console.log(`     🎯 Confianza: ${(vuln.confidence * 100).toFixed(0)}%`);
                    console.log('');
                });
            }

            // Generar archivo de reporte
            const report = scanner.generateReport(results);
            const reportPath = path.join(process.cwd(), 'security_report_improved.md');
            
            require('fs').writeFileSync(reportPath, report);
            console.log(`📝 Reporte completo guardado en: ${reportPath}`);
            
        } else {
            console.log('\n✅ NO SE ENCONTRARON VULNERABILIDADES REALES');
            console.log('🎉 ¡Proyecto limpio!');
        }

    } catch (error) {
        console.error('❌ Error durante el análisis:', error.message);
        process.exit(1);
    }
}

// Ejecutar si es llamado directamente
if (require.main === module) {
    main();
}

module.exports = { main };