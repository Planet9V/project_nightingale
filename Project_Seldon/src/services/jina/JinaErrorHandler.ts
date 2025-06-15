/**
 * JinaErrorHandler - Advanced Error Handling and Retry Logic
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import {
  JinaAPIError,
  JinaRateLimitError,
  JinaServiceType
} from '../../types/jina.js';

export interface RetryConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  jitter: boolean;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  recoveryTimeout: number;
  monitoringPeriod: number;
}

export interface ErrorMetrics {
  totalErrors: number;
  rateLimitErrors: number;
  authenticationErrors: number;
  serverErrors: number;
  networkErrors: number;
  timeoutErrors: number;
  lastError?: {
    type: string;
    message: string;
    timestamp: string;
  };
}

export enum CircuitBreakerState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open'
}

export class JinaErrorHandler {
  private retryConfig: RetryConfig;
  private circuitBreakerConfig: CircuitBreakerConfig;
  private errorMetrics: Map<JinaServiceType, ErrorMetrics> = new Map();
  private circuitBreakers: Map<JinaServiceType, {
    state: CircuitBreakerState;
    failures: number;
    lastFailure: number;
    nextAttempt: number;
  }> = new Map();
  
  private logger: Console;

  constructor(
    retryConfig: Partial<RetryConfig> = {},
    circuitBreakerConfig: Partial<CircuitBreakerConfig> = {},
    logger: Console = console
  ) {
    this.retryConfig = {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      backoffMultiplier: 2,
      jitter: true,
      ...retryConfig
    };

    this.circuitBreakerConfig = {
      failureThreshold: 5,
      recoveryTimeout: 60000, // 1 minute
      monitoringPeriod: 300000, // 5 minutes
      ...circuitBreakerConfig
    };

    this.logger = logger;
    this.initializeMetrics();
    this.initializeCircuitBreakers();
  }

  /**
   * Initialize error metrics for all services
   */
  private initializeMetrics(): void {
    const defaultMetrics: ErrorMetrics = {
      totalErrors: 0,
      rateLimitErrors: 0,
      authenticationErrors: 0,
      serverErrors: 0,
      networkErrors: 0,
      timeoutErrors: 0
    };

    this.errorMetrics.set('embedding', { ...defaultMetrics });
    this.errorMetrics.set('reranking', { ...defaultMetrics });
    this.errorMetrics.set('classifier', { ...defaultMetrics });
    this.errorMetrics.set('deepSearch', { ...defaultMetrics });
  }

  /**
   * Initialize circuit breakers for all services
   */
  private initializeCircuitBreakers(): void {
    const defaultBreaker = {
      state: CircuitBreakerState.CLOSED,
      failures: 0,
      lastFailure: 0,
      nextAttempt: 0
    };

    this.circuitBreakers.set('embedding', { ...defaultBreaker });
    this.circuitBreakers.set('reranking', { ...defaultBreaker });
    this.circuitBreakers.set('classifier', { ...defaultBreaker });
    this.circuitBreakers.set('deepSearch', { ...defaultBreaker });
  }

  /**
   * Execute operation with comprehensive error handling
   */
  async executeWithRetry<T>(
    serviceType: JinaServiceType,
    operation: () => Promise<T>,
    operationName: string = 'unknown'
  ): Promise<T> {
    // Check circuit breaker state
    if (!this.canExecute(serviceType)) {
      throw new Error(`Circuit breaker is OPEN for ${serviceType} service`);
    }

    let lastError: Error | null = null;
    let attempt = 0;

    while (attempt <= this.retryConfig.maxRetries) {
      try {
        const result = await operation();
        
        // Reset circuit breaker on success
        this.recordSuccess(serviceType);
        
        if (attempt > 0) {
          this.logger.log(`Operation ${operationName} succeeded on attempt ${attempt + 1}`);
        }
        
        return result;
      } catch (error) {
        attempt++;
        lastError = error as Error;
        
        this.recordError(serviceType, lastError);
        
        const errorType = this.classifyError(lastError);
        const shouldRetry = this.shouldRetry(errorType, attempt);
        
        this.logger.warn(
          `Attempt ${attempt}/${this.retryConfig.maxRetries + 1} failed for ${operationName} on ${serviceType}: ${lastError.message}`
        );

        if (!shouldRetry || attempt > this.retryConfig.maxRetries) {
          this.recordCircuitBreakerFailure(serviceType);
          break;
        }

        const delay = this.calculateDelay(attempt, errorType);
        this.logger.log(`Retrying in ${delay}ms...`);
        await this.sleep(delay);
      }
    }

    throw lastError || new Error(`Operation failed after ${this.retryConfig.maxRetries + 1} attempts`);
  }

  /**
   * Check if operation can be executed (circuit breaker logic)
   */
  private canExecute(serviceType: JinaServiceType): boolean {
    const breaker = this.circuitBreakers.get(serviceType);
    if (!breaker) return true;

    const now = Date.now();

    switch (breaker.state) {
      case CircuitBreakerState.CLOSED:
        return true;

      case CircuitBreakerState.OPEN:
        if (now >= breaker.nextAttempt) {
          breaker.state = CircuitBreakerState.HALF_OPEN;
          this.logger.log(`Circuit breaker for ${serviceType} moved to HALF_OPEN state`);
          return true;
        }
        return false;

      case CircuitBreakerState.HALF_OPEN:
        return true;

      default:
        return true;
    }
  }

  /**
   * Record successful operation
   */
  private recordSuccess(serviceType: JinaServiceType): void {
    const breaker = this.circuitBreakers.get(serviceType);
    if (breaker && breaker.state === CircuitBreakerState.HALF_OPEN) {
      breaker.state = CircuitBreakerState.CLOSED;
      breaker.failures = 0;
      this.logger.log(`Circuit breaker for ${serviceType} moved to CLOSED state`);
    }
  }

  /**
   * Record error and update metrics
   */
  private recordError(serviceType: JinaServiceType, error: Error): void {
    const metrics = this.errorMetrics.get(serviceType);
    if (!metrics) return;

    metrics.totalErrors++;
    metrics.lastError = {
      type: error.constructor.name,
      message: error.message,
      timestamp: new Date().toISOString()
    };

    // Classify and count specific error types
    const errorType = this.classifyError(error);
    switch (errorType) {
      case 'rate_limit':
        metrics.rateLimitErrors++;
        break;
      case 'authentication':
        metrics.authenticationErrors++;
        break;
      case 'server':
        metrics.serverErrors++;
        break;
      case 'network':
        metrics.networkErrors++;
        break;
      case 'timeout':
        metrics.timeoutErrors++;
        break;
    }
  }

  /**
   * Record circuit breaker failure
   */
  private recordCircuitBreakerFailure(serviceType: JinaServiceType): void {
    const breaker = this.circuitBreakers.get(serviceType);
    if (!breaker) return;

    breaker.failures++;
    breaker.lastFailure = Date.now();

    if (breaker.failures >= this.circuitBreakerConfig.failureThreshold) {
      breaker.state = CircuitBreakerState.OPEN;
      breaker.nextAttempt = Date.now() + this.circuitBreakerConfig.recoveryTimeout;
      
      this.logger.error(
        `Circuit breaker for ${serviceType} moved to OPEN state after ${breaker.failures} failures. ` +
        `Will retry at ${new Date(breaker.nextAttempt).toISOString()}`
      );
    }
  }

  /**
   * Classify error type for retry logic
   */
  private classifyError(error: Error): 'rate_limit' | 'authentication' | 'server' | 'network' | 'timeout' | 'client' {
    if (error instanceof JinaRateLimitError) {
      return 'rate_limit';
    }

    if (error instanceof JinaAPIError) {
      switch (error.type) {
        case 'rate_limit_error':
          return 'rate_limit';
        case 'authentication_error':
          return 'authentication';
        case 'api_error':
          return 'server';
        default:
          return 'client';
      }
    }

    const message = error.message.toLowerCase();
    
    if (message.includes('timeout')) {
      return 'timeout';
    }
    
    if (message.includes('network') || message.includes('connection') || 
        message.includes('econnreset') || message.includes('enotfound')) {
      return 'network';
    }
    
    if (message.includes('rate limit') || message.includes('429')) {
      return 'rate_limit';
    }
    
    if (message.includes('401') || message.includes('unauthorized') || 
        message.includes('authentication')) {
      return 'authentication';
    }
    
    if (message.includes('500') || message.includes('502') || 
        message.includes('503') || message.includes('504')) {
      return 'server';
    }

    return 'client';
  }

  /**
   * Determine if error should trigger retry
   */
  private shouldRetry(errorType: string): boolean {
    switch (errorType) {
      case 'rate_limit':
      case 'timeout':
      case 'network':
      case 'server':
        return true;
      case 'authentication':
      case 'client':
        return false;
      default:
        return false;
    }
  }

  /**
   * Calculate delay for retry attempt
   */
  private calculateDelay(attempt: number, errorType: string): number {
    let delay: number;

    if (errorType === 'rate_limit') {
      // Longer delay for rate limits
      delay = Math.min(60000, this.retryConfig.baseDelay * Math.pow(3, attempt - 1));
    } else {
      // Standard exponential backoff
      delay = Math.min(
        this.retryConfig.maxDelay,
        this.retryConfig.baseDelay * Math.pow(this.retryConfig.backoffMultiplier, attempt - 1)
      );
    }

    // Add jitter to prevent thundering herd
    if (this.retryConfig.jitter) {
      delay += Math.random() * 1000;
    }

    return Math.round(delay);
  }

  /**
   * Get error metrics for a specific service
   */
  getErrorMetrics(serviceType: JinaServiceType): ErrorMetrics | undefined {
    return this.errorMetrics.get(serviceType);
  }

  /**
   * Get error metrics for all services
   */
  getAllErrorMetrics(): Record<JinaServiceType, ErrorMetrics> {
    return {
      embedding: this.errorMetrics.get('embedding')!,
      reranking: this.errorMetrics.get('reranking')!,
      classifier: this.errorMetrics.get('classifier')!,
      deepSearch: this.errorMetrics.get('deepSearch')!
    };
  }

  /**
   * Get circuit breaker status for a specific service
   */
  getCircuitBreakerStatus(serviceType: JinaServiceType): {
    state: CircuitBreakerState;
    failures: number;
    canExecute: boolean;
    nextAttempt?: string;
  } {
    const breaker = this.circuitBreakers.get(serviceType);
    if (!breaker) {
      return {
        state: CircuitBreakerState.CLOSED,
        failures: 0,
        canExecute: true
      };
    }

    return {
      state: breaker.state,
      failures: breaker.failures,
      canExecute: this.canExecute(serviceType),
      nextAttempt: breaker.nextAttempt > 0 ? new Date(breaker.nextAttempt).toISOString() : undefined
    };
  }

  /**
   * Get circuit breaker status for all services
   */
  getAllCircuitBreakerStatus(): Record<JinaServiceType, ReturnType<typeof this.getCircuitBreakerStatus>> {
    return {
      embedding: this.getCircuitBreakerStatus('embedding'),
      reranking: this.getCircuitBreakerStatus('reranking'),
      classifier: this.getCircuitBreakerStatus('classifier'),
      deepSearch: this.getCircuitBreakerStatus('deepSearch')
    };
  }

  /**
   * Reset circuit breaker for a specific service
   */
  resetCircuitBreaker(serviceType: JinaServiceType): void {
    const breaker = this.circuitBreakers.get(serviceType);
    if (breaker) {
      breaker.state = CircuitBreakerState.CLOSED;
      breaker.failures = 0;
      breaker.lastFailure = 0;
      breaker.nextAttempt = 0;
      
      this.logger.log(`Circuit breaker for ${serviceType} has been reset`);
    }
  }

  /**
   * Reset all circuit breakers
   */
  resetAllCircuitBreakers(): void {
    for (const serviceType of this.circuitBreakers.keys()) {
      this.resetCircuitBreaker(serviceType);
    }
  }

  /**
   * Reset error metrics for a specific service
   */
  resetErrorMetrics(serviceType: JinaServiceType): void {
    const defaultMetrics: ErrorMetrics = {
      totalErrors: 0,
      rateLimitErrors: 0,
      authenticationErrors: 0,
      serverErrors: 0,
      networkErrors: 0,
      timeoutErrors: 0
    };

    this.errorMetrics.set(serviceType, defaultMetrics);
    this.logger.log(`Error metrics for ${serviceType} have been reset`);
  }

  /**
   * Reset all error metrics
   */
  resetAllErrorMetrics(): void {
    this.initializeMetrics();
    this.logger.log('All error metrics have been reset');
  }

  /**
   * Get comprehensive health report
   */
  getHealthReport(): {
    overall_health: 'healthy' | 'degraded' | 'critical';
    services: Record<JinaServiceType, {
      health: 'healthy' | 'degraded' | 'critical';
      error_rate: number;
      circuit_breaker_state: CircuitBreakerState;
      recent_errors: number;
    }>;
    recommendations: string[];
  } {
    const services: any = {};
    let overallHealth: 'healthy' | 'degraded' | 'critical' = 'healthy';
    const recommendations: string[] = [];

    for (const serviceType of ['embedding', 'reranking', 'classifier', 'deepSearch'] as JinaServiceType[]) {
      const metrics = this.errorMetrics.get(serviceType)!;
      const breaker = this.circuitBreakers.get(serviceType)!;
      
      const errorRate = metrics.totalErrors > 0 ? metrics.totalErrors / 100 : 0; // Simplified calculation
      const recentErrors = breaker.failures;
      
      let serviceHealth: 'healthy' | 'degraded' | 'critical' = 'healthy';
      
      if (breaker.state === CircuitBreakerState.OPEN) {
        serviceHealth = 'critical';
        overallHealth = 'critical';
        recommendations.push(`${serviceType} service is unavailable due to circuit breaker. Check connectivity and error logs.`);
      } else if (errorRate > 0.1 || recentErrors > 3) {
        serviceHealth = 'degraded';
        if (overallHealth === 'healthy') overallHealth = 'degraded';
        recommendations.push(`${serviceType} service has elevated error rates. Consider investigating recent failures.`);
      } else if (metrics.rateLimitErrors > 5) {
        serviceHealth = 'degraded';
        if (overallHealth === 'healthy') overallHealth = 'degraded';
        recommendations.push(`${serviceType} service is hitting rate limits frequently. Consider reducing request volume.`);
      }
      
      services[serviceType] = {
        health: serviceHealth,
        error_rate: errorRate,
        circuit_breaker_state: breaker.state,
        recent_errors: recentErrors
      };
    }

    return {
      overall_health: overallHealth,
      services,
      recommendations
    };
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}