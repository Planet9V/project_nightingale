/**
 * Service Factory Implementation
 * 
 * Manages all backend services with:
 * - Dependency injection
 * - Lifecycle management
 * - Health monitoring
 * - Configuration management
 * - Error handling
 */

import { 
  BackendService, 
  ServiceFactory, 
  HealthStatus, 
  ServiceMetrics, 
  ServiceStatus,
  ServiceConfig 
} from '../interfaces/BackendService';
import { logger } from '../utils/logger';

export class ServiceFactoryImpl implements ServiceFactory {
  private services: Map<string, BackendService> = new Map();
  private configs: Map<string, ServiceConfig> = new Map();
  private initialized: boolean = false;

  /**
   * Register a service with the factory
   */
  register<T extends BackendService>(name: string, service: T): void {
    if (this.services.has(name)) {
      logger.warn(`Service ${name} is already registered. Overwriting.`);
    }
    
    this.services.set(name, service);
    logger.info(`Registered service: ${name}`);
  }

  /**
   * Get a service by name
   */
  get<T extends BackendService>(name: string): T {
    const service = this.services.get(name);
    if (!service) {
      throw new Error(`Service ${name} not found. Available services: ${Array.from(this.services.keys()).join(', ')}`);
    }
    return service as T;
  }

  /**
   * Check if a service is registered
   */
  has(name: string): boolean {
    return this.services.has(name);
  }

  /**
   * Initialize all registered services
   */
  async initializeAll(): Promise<void> {
    if (this.initialized) {
      logger.warn('Services already initialized');
      return;
    }

    logger.info('Initializing all services...');
    const initPromises: Promise<void>[] = [];

    for (const [name, service] of this.services) {
      const config = this.configs.get(name) || this.createDefaultConfig(name);
      
      initPromises.push(
        this.initializeService(name, service, config)
      );
    }

    try {
      await Promise.all(initPromises);
      this.initialized = true;
      logger.info('All services initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize services:', error);
      throw error;
    }
  }

  /**
   * Initialize a single service with error handling
   */
  private async initializeService(name: string, service: BackendService, config: ServiceConfig): Promise<void> {
    try {
      logger.info(`Initializing service: ${name}`);
      await service.initialize(config);
      logger.info(`✓ Service ${name} initialized successfully`);
    } catch (error) {
      logger.error(`✗ Failed to initialize service ${name}:`, error);
      throw new Error(`Service ${name} initialization failed: ${error.message}`);
    }
  }

  /**
   * Cleanup all services
   */
  async cleanupAll(): Promise<void> {
    logger.info('Cleaning up all services...');
    const cleanupPromises: Promise<void>[] = [];

    for (const [name, service] of this.services) {
      cleanupPromises.push(
        this.cleanupService(name, service)
      );
    }

    try {
      await Promise.all(cleanupPromises);
      this.initialized = false;
      logger.info('All services cleaned up successfully');
    } catch (error) {
      logger.error('Error during service cleanup:', error);
    }
  }

  /**
   * Cleanup a single service with error handling
   */
  private async cleanupService(name: string, service: BackendService): Promise<void> {
    try {
      await service.cleanup();
      logger.info(`✓ Service ${name} cleaned up`);
    } catch (error) {
      logger.error(`✗ Error cleaning up service ${name}:`, error);
    }
  }

  /**
   * Get health status for all services
   */
  async getHealthStatus(): Promise<Record<string, HealthStatus>> {
    const healthStatus: Record<string, HealthStatus> = {};
    const healthPromises: Array<Promise<void>> = [];

    for (const [name, service] of this.services) {
      healthPromises.push(
        this.getServiceHealth(name, service).then(health => {
          healthStatus[name] = health;
        })
      );
    }

    await Promise.all(healthPromises);
    return healthStatus;
  }

  /**
   * Get health status for a single service
   */
  private async getServiceHealth(name: string, service: BackendService): Promise<HealthStatus> {
    const startTime = Date.now();
    
    try {
      const health = await Promise.race([
        service.health(),
        new Promise<HealthStatus>((_, reject) => 
          setTimeout(() => reject(new Error('Health check timeout')), 5000)
        )
      ]);
      
      return {
        ...health,
        responseTime: Date.now() - startTime
      };
    } catch (error) {
      return {
        status: ServiceStatus.ERROR,
        message: `Health check failed: ${error.message}`,
        lastChecked: new Date(),
        responseTime: Date.now() - startTime
      };
    }
  }

  /**
   * Get metrics for all services
   */
  async getServiceMetrics(): Promise<Record<string, ServiceMetrics>> {
    const metrics: Record<string, ServiceMetrics> = {};
    
    for (const [name, service] of this.services) {
      try {
        metrics[name] = service.getMetrics();
      } catch (error) {
        logger.error(`Error getting metrics for service ${name}:`, error);
        metrics[name] = {
          requestCount: 0,
          errorCount: 1,
          averageResponseTime: 0,
          lastError: {
            message: error.message,
            timestamp: new Date()
          }
        };
      }
    }
    
    return metrics;
  }

  /**
   * Update configuration for a service
   */
  async updateServiceConfig(serviceName: string, config: Partial<ServiceConfig>): Promise<void> {
    const service = this.get(serviceName);
    const currentConfig = service.getConfig();
    const newConfig = { ...currentConfig, ...config };

    // Validate new configuration
    const isValid = await service.validateConfig(newConfig);
    if (!isValid) {
      throw new Error(`Invalid configuration for service ${serviceName}`);
    }

    // Update configuration
    await service.updateConfig(config);
    this.configs.set(serviceName, newConfig);
    
    logger.info(`Configuration updated for service: ${serviceName}`);
  }

  /**
   * Get service configuration
   */
  getServiceConfig(serviceName: string): ServiceConfig {
    const service = this.get(serviceName);
    return service.getConfig();
  }

  /**
   * Create default configuration for a service
   */
  private createDefaultConfig(serviceName: string): ServiceConfig {
    return {
      name: serviceName,
      enabled: true,
      credentials: {},
      options: {},
      retryPolicy: {
        maxRetries: 3,
        backoffMs: 1000,
        timeout: 30000
      }
    };
  }

  /**
   * Register configuration for a service
   */
  registerConfig(serviceName: string, config: ServiceConfig): void {
    this.configs.set(serviceName, config);
    logger.info(`Configuration registered for service: ${serviceName}`);
  }

  /**
   * Get list of all registered services
   */
  getRegisteredServices(): Array<{name: string, initialized: boolean, description: string}> {
    return Array.from(this.services.entries()).map(([name, service]) => ({
      name,
      initialized: service.isInitialized(),
      description: service.description
    }));
  }

  /**
   * Check if all services are healthy
   */
  async areAllServicesHealthy(): Promise<boolean> {
    const healthStatuses = await this.getHealthStatus();
    return Object.values(healthStatuses).every(
      status => status.status === ServiceStatus.HEALTHY
    );
  }

  /**
   * Get services by status
   */
  async getServicesByStatus(status: ServiceStatus): Promise<string[]> {
    const healthStatuses = await this.getHealthStatus();
    return Object.entries(healthStatuses)
      .filter(([, health]) => health.status === status)
      .map(([name]) => name);
  }

  /**
   * Restart a specific service
   */
  async restartService(serviceName: string): Promise<void> {
    const service = this.get(serviceName);
    const config = this.configs.get(serviceName) || this.createDefaultConfig(serviceName);

    logger.info(`Restarting service: ${serviceName}`);
    
    try {
      await service.cleanup();
      await service.initialize(config);
      logger.info(`✓ Service ${serviceName} restarted successfully`);
    } catch (error) {
      logger.error(`✗ Failed to restart service ${serviceName}:`, error);
      throw error;
    }
  }

  /**
   * Get comprehensive system status
   */
  async getSystemStatus(): Promise<{
    healthy: boolean;
    totalServices: number;
    healthyServices: number;
    degradedServices: number;
    unhealthyServices: number;
    services: Record<string, HealthStatus>;
    metrics: Record<string, ServiceMetrics>;
  }> {
    const services = await this.getHealthStatus();
    const metrics = await this.getServiceMetrics();
    
    const statusCounts = Object.values(services).reduce((acc, status) => {
      acc[status.status] = (acc[status.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      healthy: statusCounts[ServiceStatus.UNHEALTHY] === 0 && statusCounts[ServiceStatus.ERROR] === 0,
      totalServices: Object.keys(services).length,
      healthyServices: statusCounts[ServiceStatus.HEALTHY] || 0,
      degradedServices: statusCounts[ServiceStatus.DEGRADED] || 0,
      unhealthyServices: (statusCounts[ServiceStatus.UNHEALTHY] || 0) + (statusCounts[ServiceStatus.ERROR] || 0),
      services,
      metrics
    };
  }
}

// Singleton instance
export const serviceFactory = new ServiceFactoryImpl();