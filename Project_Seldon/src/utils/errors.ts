/**
 * Error Handling Framework for Project Seldon ETL Pipeline
 * Version: 1.0.0
 * Updated: June 2025
 * 
 * This module provides comprehensive error handling for the ETL pipeline,
 * including specialized error classes, retry logic, and alert systems.
 */

import { logger } from './logger';
import { sendEmail } from '../services/notification';
import { metrics } from '../services/monitoring';

/**
 * Base error class for all ETL-related errors
 */
export class ETLError extends Error {
  public readonly code: string;
  public readonly timestamp: Date;
  public readonly context?: Record<string, any>;
  public readonly retryable: boolean;

  constructor(
    message: string,
    code: string,
    retryable: boolean = false,
    context?: Record<string, any>
  ) {
    super(message);
    this.name = 'ETLError';
    this.code = code;
    this.timestamp = new Date();
    this.retryable = retryable;
    this.context = context;

    // Ensure proper prototype chain
    Object.setPrototypeOf(this, ETLError.prototype);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      timestamp: this.timestamp,
      retryable: this.retryable,
      context: this.context,
      stack: this.stack
    };
  }
}

/**
 * Specialized error for document processing failures
 */
export class DocumentProcessingError extends ETLError {
  public readonly documentId: string;
  public readonly documentPath: string;
  public readonly processingStage: string;

  constructor(
    message: string,
    documentId: string,
    documentPath: string,
    processingStage: string,
    context?: Record<string, any>
  ) {
    super(
      message,
      'DOCUMENT_PROCESSING_ERROR',
      true, // Document processing errors are generally retryable
      { ...context, documentId, documentPath, processingStage }
    );
    this.name = 'DocumentProcessingError';
    this.documentId = documentId;
    this.documentPath = documentPath;
    this.processingStage = processingStage;

    Object.setPrototypeOf(this, DocumentProcessingError.prototype);
  }
}

/**
 * Error severity levels
 */
export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  maxAttempts: number;
  initialDelay: number;
  maxDelay: number;
  backoffFactor: number;
}

/**
 * Default retry configuration
 */
export const defaultRetryConfig: RetryConfig = {
  maxAttempts: 3,
  initialDelay: 1000, // 1 second
  maxDelay: 30000, // 30 seconds
  backoffFactor: 2
};

/**
 * Alert configuration for critical errors
 */
interface AlertConfig {
  emailRecipients: string[];
  slackWebhook?: string;
  pagerDutyKey?: string;
}

/**
 * Global error handler class
 */
export class ErrorHandler {
  private static instance: ErrorHandler;
  private alertConfig?: AlertConfig;
  private errorQueue: ETLError[] = [];
  private criticalErrorCount = 0;

  private constructor() {}

  /**
   * Get singleton instance
   */
  static getInstance(): ErrorHandler {
    if (!ErrorHandler.instance) {
      ErrorHandler.instance = new ErrorHandler();
    }
    return ErrorHandler.instance;
  }

  /**
   * Configure alert settings
   */
  configureAlerts(config: AlertConfig) {
    this.alertConfig = config;
  }

  /**
   * Handle an error with appropriate logging and alerting
   */
  async handleError(error: Error | ETLError, severity: ErrorSeverity = ErrorSeverity.MEDIUM): Promise<void> {
    // Convert to ETLError if needed
    const etlError = error instanceof ETLError ? error : new ETLError(
      error.message,
      'UNKNOWN_ERROR',
      false,
      { originalError: error.name }
    );

    // Log the error
    logger.error('Error occurred in ETL pipeline', {
      error: etlError.toJSON(),
      severity
    });

    // Track metrics
    await metrics.incrementErrorCount(etlError.code, severity);

    // Add to error queue
    this.errorQueue.push(etlError);

    // Handle critical errors
    if (severity === ErrorSeverity.CRITICAL) {
      this.criticalErrorCount++;
      await this.sendCriticalAlert(etlError);
    }

    // Check if we need to halt the pipeline
    if (this.criticalErrorCount >= 5) {
      logger.fatal('Too many critical errors, halting ETL pipeline');
      process.exit(1);
    }
  }

  /**
   * Execute a function with retry logic
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    config: Partial<RetryConfig> = {},
    context?: Record<string, any>
  ): Promise<T> {
    const retryConfig = { ...defaultRetryConfig, ...config };
    let lastError: Error | undefined;
    let delay = retryConfig.initialDelay;

    for (let attempt = 1; attempt <= retryConfig.maxAttempts; attempt++) {
      try {
        logger.debug(`Executing operation (attempt ${attempt}/${retryConfig.maxAttempts})`, context);
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        // Check if error is retryable
        if (error instanceof ETLError && !error.retryable) {
          throw error;
        }

        // Log retry attempt
        logger.warn(`Operation failed, will retry`, {
          attempt,
          maxAttempts: retryConfig.maxAttempts,
          error: error instanceof Error ? error.message : 'Unknown error',
          nextDelay: delay,
          context
        });

        // If this was the last attempt, throw the error
        if (attempt === retryConfig.maxAttempts) {
          throw new ETLError(
            `Operation failed after ${retryConfig.maxAttempts} attempts: ${lastError.message}`,
            'MAX_RETRIES_EXCEEDED',
            false,
            { originalError: lastError.message, attempts: retryConfig.maxAttempts, ...context }
          );
        }

        // Wait before next attempt
        await this.sleep(delay);
        
        // Calculate next delay with exponential backoff
        delay = Math.min(delay * retryConfig.backoffFactor, retryConfig.maxDelay);
      }
    }

    // This should never be reached, but TypeScript needs it
    throw lastError || new Error('Unexpected error in retry logic');
  }

  /**
   * Send alert for critical errors
   */
  private async sendCriticalAlert(error: ETLError): Promise<void> {
    if (!this.alertConfig) {
      logger.warn('Alert configuration not set, skipping critical error alert');
      return;
    }

    const alertMessage = this.formatAlertMessage(error);

    // Send email alert
    if (this.alertConfig.emailRecipients.length > 0) {
      try {
        await sendEmail({
          to: this.alertConfig.emailRecipients,
          subject: `[CRITICAL] ETL Pipeline Error: ${error.code}`,
          body: alertMessage,
          html: this.formatAlertHtml(error)
        });
      } catch (emailError) {
        logger.error('Failed to send email alert', { error: emailError });
      }
    }

    // Send Slack alert if configured
    if (this.alertConfig.slackWebhook) {
      try {
        await this.sendSlackAlert(this.alertConfig.slackWebhook, error);
      } catch (slackError) {
        logger.error('Failed to send Slack alert', { error: slackError });
      }
    }

    // Send PagerDuty alert if configured
    if (this.alertConfig.pagerDutyKey) {
      try {
        await this.sendPagerDutyAlert(this.alertConfig.pagerDutyKey, error);
      } catch (pdError) {
        logger.error('Failed to send PagerDuty alert', { error: pdError });
      }
    }
  }

  /**
   * Format alert message for text-based alerts
   */
  private formatAlertMessage(error: ETLError): string {
    return `
CRITICAL ETL PIPELINE ERROR

Error Code: ${error.code}
Message: ${error.message}
Timestamp: ${error.timestamp.toISOString()}
Retryable: ${error.retryable ? 'Yes' : 'No'}

Context:
${JSON.stringify(error.context, null, 2)}

Stack Trace:
${error.stack}

Critical Error Count: ${this.criticalErrorCount}
Recent Errors: ${this.errorQueue.length}
    `.trim();
  }

  /**
   * Format alert message for HTML emails
   */
  private formatAlertHtml(error: ETLError): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; }
    .error-container { background: #f8f9fa; padding: 20px; border-radius: 8px; }
    .error-header { color: #dc3545; font-size: 24px; font-weight: bold; }
    .error-details { margin-top: 20px; }
    .detail-item { margin: 10px 0; }
    .detail-label { font-weight: bold; color: #495057; }
    .detail-value { color: #212529; }
    .context-box { background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; font-family: monospace; font-size: 12px; }
    .stack-trace { background: #f1f3f4; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; white-space: pre-wrap; }
  </style>
</head>
<body>
  <div class="error-container">
    <div class="error-header">🚨 CRITICAL ETL PIPELINE ERROR</div>
    
    <div class="error-details">
      <div class="detail-item">
        <span class="detail-label">Error Code:</span>
        <span class="detail-value">${error.code}</span>
      </div>
      
      <div class="detail-item">
        <span class="detail-label">Message:</span>
        <span class="detail-value">${error.message}</span>
      </div>
      
      <div class="detail-item">
        <span class="detail-label">Timestamp:</span>
        <span class="detail-value">${error.timestamp.toISOString()}</span>
      </div>
      
      <div class="detail-item">
        <span class="detail-label">Retryable:</span>
        <span class="detail-value">${error.retryable ? '✅ Yes' : '❌ No'}</span>
      </div>
      
      <div class="detail-item">
        <span class="detail-label">Context:</span>
        <div class="context-box">${JSON.stringify(error.context, null, 2)}</div>
      </div>
      
      <div class="detail-item">
        <span class="detail-label">Stack Trace:</span>
        <div class="stack-trace">${error.stack}</div>
      </div>
      
      <div class="detail-item" style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6;">
        <span class="detail-label">System Status:</span>
        <ul>
          <li>Critical Error Count: ${this.criticalErrorCount}</li>
          <li>Recent Errors in Queue: ${this.errorQueue.length}</li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>
    `;
  }

  /**
   * Send Slack alert
   */
  private async sendSlackAlert(webhook: string, error: ETLError): Promise<void> {
    const payload = {
      text: `🚨 Critical ETL Pipeline Error`,
      attachments: [{
        color: 'danger',
        fields: [
          { title: 'Error Code', value: error.code, short: true },
          { title: 'Retryable', value: error.retryable ? 'Yes' : 'No', short: true },
          { title: 'Message', value: error.message, short: false },
          { title: 'Timestamp', value: error.timestamp.toISOString(), short: false }
        ],
        footer: 'Project Seldon ETL Pipeline',
        ts: Math.floor(Date.now() / 1000)
      }]
    };

    const response = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Slack webhook failed: ${response.statusText}`);
    }
  }

  /**
   * Send PagerDuty alert
   */
  private async sendPagerDutyAlert(integrationKey: string, error: ETLError): Promise<void> {
    const payload = {
      routing_key: integrationKey,
      event_action: 'trigger',
      dedup_key: `etl-error-${error.code}-${Date.now()}`,
      payload: {
        summary: `Critical ETL Error: ${error.message}`,
        severity: 'critical',
        source: 'project-seldon-etl',
        timestamp: error.timestamp.toISOString(),
        custom_details: {
          error_code: error.code,
          retryable: error.retryable,
          context: error.context,
          critical_error_count: this.criticalErrorCount
        }
      }
    };

    const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`PagerDuty alert failed: ${response.statusText}`);
    }
  }

  /**
   * Helper function to sleep for a specified duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get error statistics
   */
  getErrorStats() {
    const errorsByCode = this.errorQueue.reduce((acc, error) => {
      acc[error.code] = (acc[error.code] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalErrors: this.errorQueue.length,
      criticalErrors: this.criticalErrorCount,
      errorsByCode,
      recentErrors: this.errorQueue.slice(-10).map(e => ({
        code: e.code,
        message: e.message,
        timestamp: e.timestamp
      }))
    };
  }

  /**
   * Clear error queue (use with caution)
   */
  clearErrorQueue() {
    this.errorQueue = [];
    this.criticalErrorCount = 0;
  }
}

// Export singleton instance
export const errorHandler = ErrorHandler.getInstance();

// ============================================
// ✅ PROGRESS MARKER: Error Handling Framework Complete
// ============================================
// The error handling framework has been successfully implemented with:
// 1. ETLError base class with comprehensive error tracking
// 2. DocumentProcessingError specialized class for document-specific errors
// 3. Global error handler with exponential backoff retry logic
// 4. Multi-channel alert system (Email, Slack, PagerDuty) for critical errors
// 5. Error statistics and monitoring capabilities
// 
// Next Steps:
// - Task 7: Set up monitoring service (monitoring.ts)
// - Task 8: Create notification service (notification.ts)
// ============================================