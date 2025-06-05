/**
 * Base Service Implementation
 * 
 * Provides common functionality for all backend services:
 * - Configuration management
 * - Health monitoring
 * - Metrics collection
 * - Error handling
 * - Lifecycle management
 */

import { 
  BackendService, 
  ServiceConfig, 
  HealthStatus, 
  ServiceMetrics, 
  ServiceStatus 
} from '../interfaces/BackendService';
import { logger } from '../utils/logger';

export abstract class BaseService implements BackendService {
  protected config: ServiceConfig;
  protected initialized: boolean = false;
  protected metrics: ServiceMetrics = {
    requestCount: 0,
    errorCount: 0,
    averageResponseTime: 0
  };
  private responseTimes: number[] = [];

  constructor(
    public readonly name: string,
    public readonly version: string,
    public readonly description: string
  ) {}

  /**
   * Initialize the service with configuration
   */
  async initialize(config: ServiceConfig): Promise<void> {
    if (this.initialized) {
      logger.warn(`Service ${this.name} is already initialized`);
      return;
    }

    try {
      logger.info(`Initializing ${this.name} service...`);
      
      // Validate configuration
      const isValid = await this.validateConfig(config);
      if (!isValid) {
        throw new Error(`Invalid configuration for ${this.name}`);
      }

      this.config = config;
      
      // Call service-specific initialization
      await this.onInitialize();
      
      this.initialized = true;
      logger.info(`✓ ${this.name} service initialized successfully`);
      
    } catch (error) {
      logger.error(`✗ Failed to initialize ${this.name} service:`, error);
      throw error;
    }
  }

  /**
   * Cleanup service resources
   */
  async cleanup(): Promise<void> {
    if (!this.initialized) {
      return;
    }

    try {
      logger.info(`Cleaning up ${this.name} service...`);
      
      // Call service-specific cleanup
      await this.onCleanup();
      
      this.initialized = false;
      logger.info(`✓ ${this.name} service cleaned up`);
      
    } catch (error) {
      logger.error(`✗ Error cleaning up ${this.name} service:`, error);
      throw error;
    }
  }

  /**
   * Check if service is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get service health status
   */
  async health(): Promise<HealthStatus> {
    const startTime = Date.now();
    
    try {
      // Call service-specific health check
      const isHealthy = await this.checkHealth();
      const responseTime = Date.now() - startTime;
      
      return {
        status: isHealthy ? ServiceStatus.HEALTHY : ServiceStatus.UNHEALTHY,
        message: isHealthy ? 'Service is healthy' : 'Service is unhealthy',
        lastChecked: new Date(),
        responseTime,
        details: await this.getHealthDetails()
      };
      
    } catch (error) {
      return {
        status: ServiceStatus.ERROR,
        message: `Health check failed: ${error.message}`,
        lastChecked: new Date(),
        responseTime: Date.now() - startTime,
        details: { error: error.message }
      };
    }
  }

  /**
   * Get service metrics
   */
  getMetrics(): ServiceMetrics {
    return { ...this.metrics };
  }

  /**
   * Get service configuration
   */
  getConfig(): ServiceConfig {
    return { ...this.config };
  }

  /**
   * Update service configuration
   */
  async updateConfig(newConfig: Partial<ServiceConfig>): Promise<void> {
    const updatedConfig = { ...this.config, ...newConfig };
    
    // Validate new configuration
    const isValid = await this.validateConfig(updatedConfig);
    if (!isValid) {
      throw new Error(`Invalid configuration update for ${this.name}`);
    }

    const oldConfig = this.config;
    this.config = updatedConfig;

    try {
      // Call service-specific configuration update
      await this.onConfigUpdate(oldConfig, updatedConfig);
      logger.info(`Configuration updated for ${this.name} service`);
    } catch (error) {
      // Rollback configuration on error
      this.config = oldConfig;
      logger.error(`Failed to update configuration for ${this.name}:`, error);
      throw error;
    }
  }

  /**
   * Validate service configuration
   */
  async validateConfig(config: ServiceConfig): Promise<boolean> {
    try {
      // Basic validation
      if (!config.name || typeof config.enabled !== 'boolean') {
        return false;
      }

      // Call service-specific validation
      return await this.onValidateConfig(config);
    } catch (error) {
      logger.error(`Configuration validation failed for ${this.name}:`, error);
      return false;
    }
  }

  /**
   * Record a request for metrics
   */
  protected recordRequest(): void {
    this.metrics.requestCount++;
    this.onRequest?.({ service: this.name, timestamp: new Date() });
  }

  /**
   * Record a successful response for metrics
   */
  protected recordResponse(responseTime: number, result?: any): void {
    this.responseTimes.push(responseTime);
    
    // Keep only last 100 response times for average calculation
    if (this.responseTimes.length > 100) {
      this.responseTimes = this.responseTimes.slice(-100);
    }
    
    this.metrics.averageResponseTime = 
      this.responseTimes.reduce((sum, time) => sum + time, 0) / this.responseTimes.length;
    
    this.onResponse?.({ service: this.name, responseTime }, result);
  }

  /**
   * Record an error for metrics
   */
  protected recordError(error: Error, context?: Record<string, any>): void {
    this.metrics.errorCount++;
    this.metrics.lastError = {
      message: error.message,
      timestamp: new Date(),
      context
    };
    
    logger.error(`Error in ${this.name} service:`, error);
    this.onError?.(error, { service: this.name, ...context });
  }

  /**
   * Execute a service operation with automatic metrics recording
   */
  protected async executeWithMetrics<T>(
    operation: () => Promise<T>,
    context?: Record<string, any>
  ): Promise<T> {
    const startTime = Date.now();
    this.recordRequest();

    try {
      const result = await operation();
      this.recordResponse(Date.now() - startTime, result);
      return result;
    } catch (error) {
      this.recordError(error, context);
      throw error;
    }
  }

  /**
   * Execute operation with retry logic
   */
  protected async executeWithRetry<T>(
    operation: () => Promise<T>,
    context?: Record<string, any>
  ): Promise<T> {
    const retryPolicy = this.config?.retryPolicy || {
      maxRetries: 3,
      backoffMs: 1000,
      timeout: 30000
    };

    let lastError: Error;
    
    for (let attempt = 0; attempt <= retryPolicy.maxRetries; attempt++) {
      try {
        // Add timeout to operation
        return await Promise.race([
          operation(),
          new Promise<never>((_, reject) => 
            setTimeout(() => reject(new Error('Operation timeout')), retryPolicy.timeout)
          )
        ]);
      } catch (error) {
        lastError = error;
        
        if (attempt < retryPolicy.maxRetries) {
          const backoffTime = retryPolicy.backoffMs * Math.pow(2, attempt);
          logger.warn(`${this.name} operation failed, retrying in ${backoffTime}ms...`);
          await new Promise(resolve => setTimeout(resolve, backoffTime));
        }
      }
    }
    
    throw lastError;
  }

  // Abstract methods that must be implemented by concrete services

  /**
   * Service-specific initialization logic
   */
  protected abstract onInitialize(): Promise<void>;

  /**
   * Service-specific cleanup logic
   */
  protected abstract onCleanup(): Promise<void>;

  /**
   * Service-specific health check logic
   */
  protected abstract checkHealth(): Promise<boolean>;

  /**
   * Service-specific health details
   */
  protected abstract getHealthDetails(): Promise<Record<string, any>>;

  /**
   * Service-specific configuration validation
   */
  protected abstract onValidateConfig(config: ServiceConfig): Promise<boolean>;

  /**
   * Service-specific configuration update handling
   */
  protected abstract onConfigUpdate(oldConfig: ServiceConfig, newConfig: ServiceConfig): Promise<void>;

  // Optional event hooks
  onRequest?(context: Record<string, any>): void;
  onResponse?(context: Record<string, any>, result: any): void;
  onError?(error: Error, context: Record<string, any>): void;
}