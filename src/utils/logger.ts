/**
 * Sistema de Logging Seguro para Producción
 * Reemplaza console.log statements con logging estructurado
 */

interface LogEntry {
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  context?: Record<string, any>;
  environment: 'development' | 'production';
}

class SecureLogger {
  private isDevelopment: boolean;
  private logQueue: LogEntry[] = [];

  constructor() {
    this.isDevelopment = import.meta.env.DEV;
  }

  private createLogEntry(
    level: LogEntry['level'], 
    message: string, 
    context?: Record<string, any>
  ): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
      environment: this.isDevelopment ? 'development' : 'production'
    };
  }

  private shouldLog(level: LogEntry['level']): boolean {
    const logLevels = { debug: 0, info: 1, warn: 2, error: 3 };
    const currentLevel = this.isDevelopment ? 0 : 1; // Solo info+ en producción
    
    return logLevels[level] >= currentLevel;
  }

  private async persistLog(entry: LogEntry): Promise<void> {
    if (!this.shouldLog(entry.level)) return;

    // En desarrollo, usar console solo si es apropiado
    if (this.isDevelopment && entry.level !== 'error') {
      const style = this.getConsoleStyle(entry.level);
      console.log(`%c[${entry.level.toUpperCase()}] ${entry.message}`, style);
    }

    // En producción, enviar logs a endpoint seguro o localStorage
    if (!this.isDevelopment) {
      this.queueForTransmission(entry);
    }
  }

  private getConsoleStyle(level: LogEntry['level']): string {
    const styles = {
      debug: 'color: #6c757d',
      info: 'color: #0d6efd',
      warn: 'color: #ffc107',
      error: 'color: #dc3545; font-weight: bold'
    };
    return styles[level];
  }

  private queueForTransmission(entry: LogEntry): void {
    // En producción real, esto enviaría a un servicio de logging
    // Por ahora, almacenamos localmente sin exponer información sensible
    this.logQueue.push(entry);
    
    // Limitar cola de logs para evitar uso excesivo de memoria
    if (this.logQueue.length > 50) {
      this.logQueue = this.logQueue.slice(-25);
    }
  }

  debug(message: string, context?: Record<string, any>): void {
    const entry = this.createLogEntry('debug', message, context);
    this.persistLog(entry);
  }

  info(message: string, context?: Record<string, any>): void {
    const entry = this.createLogEntry('info', message, this.sanitizeContext(context));
    this.persistLog(entry);
  }

  warn(message: string, context?: Record<string, any>): void {
    const entry = this.createLogEntry('warn', message, this.sanitizeContext(context));
    this.persistLog(entry);
  }

  error(message: string, context?: Record<string, any>): void {
    const entry = this.createLogEntry('error', message, this.sanitizeContext(context));
    this.persistLog(entry);
  }

  private sanitizeContext(context?: Record<string, any>): Record<string, any> | undefined {
    if (!context) return context;

    // Remover datos sensibles comunes
    const sensitivePatterns = [
      'password', 'token', 'key', 'secret', 'auth',
      'cookie', 'session', 'credential', 'private'
    ];

    const sanitized: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(context)) {
      const isSensitive = sensitivePatterns.some(pattern => 
        key.toLowerCase().includes(pattern)
      );
      
      if (isSensitive) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = typeof value === 'string' ? 
          this.sanitizeString(value) : value;
      }
    }
    
    return sanitized;
  }

  private sanitizeString(str: string): string {
    // Remover patrones potencialmente sensibles en strings
    return str
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]')
      .replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[CARD]')
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]');
  }

  // Método para análisis de seguridad
  analyzeSecurityLogs(): { level: 'low' | 'medium' | 'high'; issues: string[] } {
    const issues: string[] = [];
    let maxLevel: 'low' | 'medium' | 'high' = 'low';

    this.logQueue.forEach(entry => {
      if (entry.message.toLowerCase().includes('error')) {
        issues.push(`Error detectado: ${entry.message}`);
        maxLevel = 'medium';
      }
      if (entry.context && JSON.stringify(entry.context).includes('sensitive')) {
        issues.push('Posible exposición de datos sensibles');
        maxLevel = 'high';
      }
    });

    return { level: maxLevel, issues };
  }
}

// Instancia singleton del logger
export const logger = new SecureLogger();

// Funciones de conveniencia para mantener compatibilidad con el código existente
export const debug = (message: string, context?: Record<string, any>) => logger.debug(message, context);
export const info = (message: string, context?: Record<string, any>) => logger.info(message, context);
export const warn = (message: string, context?: Record<string, any>) => logger.warn(message, context);
export const error = (message: string, context?: Record<string, any>) => logger.error(message, context);

export default logger;