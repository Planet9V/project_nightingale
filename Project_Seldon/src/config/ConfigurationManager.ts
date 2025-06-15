/**
 * Configuration Manager for Project Seldon ETL Pipeline
 * Handles environment variables, validation, and configuration loading
 */

import * as dotenv from 'dotenv';
import { z } from 'zod';
import * as path from 'path';
import { promises as fs } from 'fs';
import { Configuration, IConfigurationManager, ConfigurationValidationResult } from './types';
import { VectorDBProvider } from '../types/database';

// Load environment variables from the correct path
const envPath = path.join(process.cwd(), '.env');
dotenv.config({ path: envPath });

// Lazy load logger to avoid circular dependency
let logger: any;
const getLogger = () => {
  if (!logger) {
    logger = require('../utils/logger').logger;
  }
  return logger;
};

// Configuration Schema - Updated to match the unified Configuration interface
const ConfigurationSchema = z.object({
  // Environment
  environment: z.enum(['development', 'staging', 'production']).default('development'),
  
  // ETL Configuration
  etl: z.object({
    environment: z.enum(['development', 'staging', 'production']).default('development'),
    batchSize: z.number().min(1).max(1000).default(50),
    maxRetries: z.number().min(0).max(10).default(3),
    retryDelay: z.number().min(1000).max(60000).default(5000),
    concurrency: z.number().min(1).max(50).default(5),
    timeout: z.number().min(10000).max(3600000).default(300000), // 5 minutes
    enableMetrics: z.boolean().default(true),
    enableTracing: z.boolean().default(true),
  }),
  
  // Database Configuration - Updated to match DatabaseConfig interface
  databases: z.object({
    postgres: z.object({
      host: z.string().default('localhost'),
      port: z.number().default(5432),
      database: z.string().default('project_seldon'),
      user: z.string().min(1),
      password: z.string().min(1),
      ssl: z.union([z.boolean(), z.object({
        rejectUnauthorized: z.boolean().optional(),
        ca: z.string().optional(),
        cert: z.string().optional(),
        key: z.string().optional(),
      })]).optional(),
      poolConfig: z.object({
        min: z.number().default(2),
        max: z.number().default(10),
        idleTimeoutMillis: z.number().default(10000),
        connectionTimeoutMillis: z.number().default(5000),
      }),
      schema: z.string().default('public'),
    }),
    vector: z.object({
      provider: z.nativeEnum(VectorDBProvider).default(VectorDBProvider.PINECONE),
      connectionString: z.string().min(1),
      apiKey: z.string().optional(),
      environment: z.string().optional(),
      options: z.record(z.any()).optional(),
    }),
    monitoring: z.object({
      healthCheckInterval: z.number().default(60000),
      metricsInterval: z.number().default(30000),
      enablePrometheus: z.boolean().default(true),
      prometheusPort: z.number().default(9090),
      logging: z.object({
        level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
        directory: z.string().default('./logs'),
        maxFileSize: z.number().default(10 * 1024 * 1024),
        maxFiles: z.number().default(5),
        enableConsole: z.boolean().default(true),
        enableFile: z.boolean().default(true),
      }),
    }),
  }),
  
  // AI Service Configuration
  ai: z.object({
    jina: z.object({
      apiKey: z.string().min(1),
      baseUrl: z.string().url().default('https://api.jina.ai/v1'),
      embeddingModel: z.string().default('jina-embeddings-v2-base-en'),
      rerankModel: z.string().default('jina-reranker-v2-base-multilingual'),
      classifierModel: z.string().default('jina-clip-v1'),
      maxTokens: z.number().default(8192),
      rateLimit: z.object({
        requestsPerMinute: z.number().default(50),
        requestsPerHour: z.number().default(1000),
        burstLimit: z.number().default(10),
      }),
    }),
    openai: z.object({
      apiKey: z.string().min(1),
      organization: z.string().optional(),
      model: z.string().default('gpt-3.5-turbo'),
      maxTokens: z.number().default(4096),
    }).optional(),
    anthropic: z.object({
      apiKey: z.string().min(1),
      model: z.string().default('claude-3-sonnet'),
      maxTokens: z.number().default(4096),
    }).optional(),
  }),
  
  // Storage Configuration
  storage: z.object({
    local: z.object({
      tempDirectory: z.string().default('/tmp/project-seldon'),
      outputDirectory: z.string().default('./output'),
      maxFileSize: z.number().default(100 * 1024 * 1024), // 100MB
    }),
    s3: z.object({
      bucket: z.string().min(1),
      region: z.string().min(1),
      accessKeyId: z.string().min(1),
      secretAccessKey: z.string().min(1),
      endpoint: z.string().optional(),
    }).optional(),
    gcs: z.object({
      bucket: z.string().min(1),
      projectId: z.string().min(1),
      keyFilePath: z.string().min(1),
    }).optional(),
  }),
  
  // Monitoring Configuration
  monitoring: z.object({
    healthCheckInterval: z.number().default(60000),
    metricsInterval: z.number().default(30000),
    enablePrometheus: z.boolean().default(true),
    prometheusPort: z.number().default(9090),
    logging: z.object({
      level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
      directory: z.string().default('./logs'),
      maxFileSize: z.number().default(10 * 1024 * 1024),
      maxFiles: z.number().default(5),
      enableConsole: z.boolean().default(true),
      enableFile: z.boolean().default(true),
    }),
  }),
  
  // Optional configurations
  processing: z.object({
    chunkSize: z.number().min(100).max(8192).default(1000),
    chunkOverlap: z.number().min(0).max(500).default(100),
    maxDocumentSize: z.number().default(10 * 1024 * 1024),
    supportedFormats: z.array(z.string()).default(['.md', '.txt', '.pdf', '.json']),
    enableOCR: z.boolean().default(false),
    ocrLanguages: z.array(z.string()).default(['en']),
  }).optional(),
  
  security: z.object({
    encryption: z.object({
      enabled: z.boolean().default(false),
      algorithm: z.string().default('aes-256-gcm'),
      keyRotationInterval: z.number().default(30 * 24 * 60 * 60 * 1000), // 30 days
    }),
    authentication: z.object({
      type: z.enum(['apiKey', 'oauth', 'jwt']).default('apiKey'),
      tokenExpiry: z.number().default(3600), // 1 hour
    }),
    rateLimit: z.object({
      enabled: z.boolean().default(true),
      windowMs: z.number().default(60000),
      maxRequests: z.number().default(100),
    }),
  }).optional(),
  
  features: z.object({
    enableCaching: z.boolean().default(true),
    enableAsyncProcessing: z.boolean().default(true),
    enableAutoScaling: z.boolean().default(false),
    enableDebugMode: z.boolean().default(false),
  }).optional(),
  
  api: z.object({
    port: z.number().default(3000),
    host: z.string().default('localhost'),
    basePath: z.string().default('/api/v1'),
    corsOrigins: z.array(z.string()).default(['http://localhost:3000']),
    timeout: z.number().default(30000),
  }).optional(),
});

// Remove the local Configuration type definition since we're importing it
// export type Configuration = z.infer<typeof ConfigurationSchema>;

export class ConfigurationManager implements IConfigurationManager {
  private static instance: ConfigurationManager;
  private configuration: Configuration | null = null;
  private configFile: string;
  private watchCallback?: (config: Configuration) => void;

  private constructor() {
    this.configFile = path.join(
      process.cwd(),
      'config',
      `${process.env.NODE_ENV || 'development'}.json`
    );
  }

  public static getInstance(): ConfigurationManager {
    if (!ConfigurationManager.instance) {
      ConfigurationManager.instance = new ConfigurationManager();
    }
    return ConfigurationManager.instance;
  }

  /**
   * Load and validate configuration
   */
  public async load(): Promise<Configuration> {
    if (this.configuration) {
      return this.configuration;
    }

    try {
      const log = getLogger();
      log.info('Loading configuration', { 
        environment: process.env.NODE_ENV || 'development',
        configFile: this.configFile 
      });

      // Build configuration from environment variables and config file
      const rawConfig = await this.buildConfiguration();
      
      // Validate configuration
      const result = ConfigurationSchema.safeParse(rawConfig);
      
      if (!result.success) {
        const errors = result.error.errors.map(err => ({
          path: err.path.join('.'),
          message: err.message,
        }));
        throw new Error(`Configuration validation failed: ${JSON.stringify(errors)}`);
      }

      this.configuration = result.data;
      
      // Mask sensitive values for logging
      const maskedConfig = this.maskSensitiveValues(this.configuration);
      log.info('Configuration loaded successfully', { config: maskedConfig });

      return this.configuration;
    } catch (error) {
      const log = getLogger();
      log.error('Failed to load configuration', error as Error);
      throw error;
    }
  }

  /**
   * Get current configuration
   */
  public get(): Configuration {
    if (!this.configuration) {
      throw new Error('Configuration not loaded. Call load() first.');
    }
    return this.configuration;
  }

  /**
   * Validate configuration health
   */
  public async validate(): Promise<ConfigurationValidationResult> {
    const errors: any[] = [];
    const warnings: any[] = [];
    
    try {
      const config = this.get();
      
      // Check required directories exist
      if (config.storage?.local?.tempDirectory) {
        await this.ensureDirectoryExists(config.storage.local.tempDirectory);
      }
      if (config.monitoring?.logging?.directory) {
        await this.ensureDirectoryExists(config.monitoring.logging.directory);
      }

      // Validate API keys are not default/empty
      if (config.ai.jina.apiKey === 'your-jina-api-key' || !config.ai.jina.apiKey) {
        errors.push({
          path: 'ai.jina.apiKey',
          message: 'Jina API key not configured',
        });
      }

      // Check database configurations
      if (!config.databases.postgres.user || !config.databases.postgres.password) {
        errors.push({
          path: 'databases.postgres',
          message: 'PostgreSQL credentials not configured',
        });
      }

      // Warnings for optional features
      if (!config.features?.enableCaching) {
        warnings.push({
          path: 'features.enableCaching',
          message: 'Caching is disabled, this may impact performance',
          suggestion: 'Enable caching for better performance in production',
        });
      }

      if (config.environment === 'production' && !config.security?.encryption?.enabled) {
        warnings.push({
          path: 'security.encryption.enabled',
          message: 'Encryption is disabled in production environment',
          suggestion: 'Enable encryption for production deployments',
        });
      }

      const log = getLogger();
      if (errors.length === 0) {
        log.info('Configuration validation successful', { warnings: warnings.length });
      } else {
        log.error('Configuration validation failed', { errors: errors.length, warnings: warnings.length });
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
      };
    } catch (error) {
      const log = getLogger();
      log.error('Configuration validation failed', error as Error);
      
      errors.push({
        path: 'general',
        message: error instanceof Error ? error.message : 'Unknown validation error',
      });
      
      return {
        valid: false,
        errors,
        warnings,
      };
    }
  }

  /**
   * Watch for configuration changes
   */
  public watch(callback: (config: Configuration) => void): void {
    this.watchCallback = callback;
    // In a real implementation, this would set up file watchers or polling
    // For now, we'll just store the callback for potential future use
  }

  /**
   * Stop watching for configuration changes
   */
  public unwatch(): void {
    this.watchCallback = undefined;
    // In a real implementation, this would clean up file watchers
  }

  /**
   * Build configuration from multiple sources
   */
  private async buildConfiguration(): Promise<any> {
    const environment = process.env.NODE_ENV || 'development';
    
    const config: any = {
      environment,
      etl: {
        environment,
        batchSize: parseInt(process.env.BATCH_SIZE || '5', 10),
        maxRetries: parseInt(process.env.ETL_MAX_RETRIES || '3', 10),
        retryDelay: parseInt(process.env.ETL_RETRY_DELAY || '5000', 10),
        concurrency: parseInt(process.env.MAX_CONCURRENT_JOBS || '3', 10),
        timeout: parseInt(process.env.ETL_TIMEOUT || '300000', 10),
        enableMetrics: process.env.ETL_ENABLE_METRICS !== 'false',
        enableTracing: process.env.ETL_ENABLE_TRACING !== 'false',
      },
      databases: {
        postgres: {
          host: process.env.POSTGRES_HOST || process.env.SUPABASE_URL?.replace('https://', '').split('.')[0] + '.supabase.co' || 'localhost',
          port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
          database: process.env.POSTGRES_DATABASE || 'postgres',
          user: process.env.POSTGRES_USER || 'postgres',
          password: process.env.POSTGRES_PASSWORD || process.env.SUPABASE_SERVICE_KEY || '',
          ssl: process.env.POSTGRES_SSL === 'true' || process.env.NODE_ENV === 'production',
          poolConfig: {
            min: parseInt(process.env.POSTGRES_POOL_MIN || '2', 10),
            max: parseInt(process.env.POSTGRES_POOL_MAX || '10', 10),
            idleTimeoutMillis: parseInt(process.env.POSTGRES_IDLE_TIMEOUT || '10000', 10),
            connectionTimeoutMillis: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '5000', 10),
          },
          schema: process.env.POSTGRES_SCHEMA || 'public',
        },
        vector: {
          provider: VectorDBProvider.PINECONE,
          connectionString: process.env.PINECONE_ENVIRONMENT || 'gcp-starter',
          apiKey: process.env.PINECONE_API_KEY || '',
          environment: process.env.PINECONE_ENVIRONMENT || 'gcp-starter',
          options: {
            indexName: process.env.PINECONE_INDEX_NAME || 'nightingale',
            dimension: parseInt(process.env.EMBEDDING_DIMENSIONS || '768', 10),
            metric: process.env.PINECONE_METRIC || 'cosine',
          },
        },
        monitoring: {
          healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '60000', 10),
          metricsInterval: parseInt(process.env.METRICS_INTERVAL || '30000', 10),
          enablePrometheus: process.env.ENABLE_PROMETHEUS !== 'false',
          prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9090', 10),
          logging: {
            level: process.env.LOG_LEVEL || 'info',
            directory: process.env.LOG_DIRECTORY || 'logs',
            maxFileSize: parseInt(process.env.LOG_MAX_FILE_SIZE || '10485760', 10),
            maxFiles: parseInt(process.env.LOG_MAX_FILES || '5', 10),
            enableConsole: process.env.LOG_ENABLE_CONSOLE !== 'false',
            enableFile: process.env.LOG_ENABLE_FILE !== 'false',
          },
        },
      },
      ai: {
        jina: {
          apiKey: process.env.JINA_API_KEY || '',
          baseUrl: process.env.JINA_BASE_URL || 'https://api.jina.ai/v1',
          embeddingModel: process.env.JINA_EMBEDDING_MODEL || 'jina-embeddings-v2-base-en',
          rerankModel: process.env.JINA_RERANK_MODEL || 'jina-reranker-v2-base-multilingual',
          classifierModel: process.env.JINA_CLASSIFIER_MODEL || 'jina-clip-v1',
          maxTokens: parseInt(process.env.JINA_MAX_TOKENS || '8192', 10),
          rateLimit: {
            requestsPerMinute: parseInt(process.env.JINA_EMBEDDING_RATE_LIMIT || '2000', 10),
            requestsPerHour: parseInt(process.env.JINA_RATE_LIMIT_RPH || '1000', 10),
            burstLimit: parseInt(process.env.JINA_RATE_LIMIT_BURST || '10', 10),
          },
        },
      },
      storage: {
        local: {
          tempDirectory: process.env.TEMP_DIRECTORY || '/tmp/project-seldon',
          outputDirectory: process.env.OUTPUT_DIRECTORY || './output',
          maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '104857600', 10), // 100MB
        },
      },
      monitoring: {
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '60000', 10),
        metricsInterval: parseInt(process.env.METRICS_INTERVAL || '30000', 10),
        enablePrometheus: process.env.ENABLE_PROMETHEUS !== 'false',
        prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9090', 10),
        logging: {
          level: process.env.LOG_LEVEL || 'info',
          directory: process.env.LOG_DIRECTORY || 'logs',
          maxFileSize: parseInt(process.env.LOG_MAX_FILE_SIZE || '10485760', 10),
          maxFiles: parseInt(process.env.LOG_MAX_FILES || '5', 10),
          enableConsole: process.env.LOG_ENABLE_CONSOLE !== 'false',
          enableFile: process.env.LOG_ENABLE_FILE !== 'false',
        },
      },
      processing: {
        chunkSize: parseInt(process.env.CHUNK_SIZE || '1500', 10),
        chunkOverlap: parseInt(process.env.CHUNK_OVERLAP || '200', 10),
        maxDocumentSize: parseInt(process.env.MAX_DOCUMENT_SIZE || '10485760', 10),
        supportedFormats: (process.env.SUPPORTED_FORMATS || '.md,.txt,.pdf,.json').split(','),
        enableOCR: process.env.ENABLE_OCR === 'true',
        ocrLanguages: (process.env.OCR_LANGUAGES || 'en').split(','),
      },
    };

    // Try to load from config file if it exists
    try {
      const fileConfig = await this.loadConfigFile();
      if (fileConfig) {
        // Deep merge with environment variables taking precedence
        return this.deepMerge(fileConfig, config);
      }
    } catch (error) {
      // Silently continue - config file is optional
    }

    return config;
  }

  /**
   * Load configuration from file
   */
  private async loadConfigFile(): Promise<any> {
    try {
      const content = await fs.readFile(this.configFile, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }

  /**
   * Deep merge two objects
   */
  private deepMerge(target: any, source: any): any {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else if (source[key] !== undefined && source[key] !== '') {
        result[key] = source[key];
      }
    }
    
    return result;
  }

  /**
   * Mask sensitive values for logging
   */
  private maskSensitiveValues(config: Configuration): any {
    const masked = JSON.parse(JSON.stringify(config));
    
    // Mask database passwords and API keys
    if (masked.databases?.postgres?.password) {
      masked.databases.postgres.password = this.maskString(masked.databases.postgres.password);
    }
    if (masked.databases?.vector?.apiKey) {
      masked.databases.vector.apiKey = this.maskString(masked.databases.vector.apiKey);
    }
    
    // Mask AI service API keys
    if (masked.ai?.jina?.apiKey) {
      masked.ai.jina.apiKey = this.maskString(masked.ai.jina.apiKey);
    }
    if (masked.ai?.openai?.apiKey) {
      masked.ai.openai.apiKey = this.maskString(masked.ai.openai.apiKey);
    }
    if (masked.ai?.anthropic?.apiKey) {
      masked.ai.anthropic.apiKey = this.maskString(masked.ai.anthropic.apiKey);
    }
    
    // Mask storage credentials
    if (masked.storage?.s3?.accessKeyId) {
      masked.storage.s3.accessKeyId = this.maskString(masked.storage.s3.accessKeyId);
    }
    if (masked.storage?.s3?.secretAccessKey) {
      masked.storage.s3.secretAccessKey = this.maskString(masked.storage.s3.secretAccessKey);
    }
    
    return masked;
  }

  /**
   * Mask a string value
   */
  private maskString(value: string): string {
    if (value.length <= 8) {
      return '***';
    }
    return value.substring(0, 4) + '***' + value.substring(value.length - 4);
  }

  /**
   * Ensure directory exists
   */
  private async ensureDirectoryExists(dir: string): Promise<void> {
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  /**
   * Reload configuration
   */
  public async reload(): Promise<Configuration> {
    this.configuration = null;
    return this.load();
  }

  /**
   * Get a specific configuration value by path
   */
  public getValue<T>(path: string): T {
    const config = this.get();
    const keys = path.split('.');
    let value: any = config;
    
    for (const key of keys) {
      value = value[key];
      if (value === undefined) {
        throw new Error(`Configuration value not found: ${path}`);
      }
    }
    
    return value as T;
  }
}

// Export singleton instance
export const configManager = ConfigurationManager.getInstance();

// Also export the Configuration type from types.ts for convenience
export type { Configuration, ConfigurationValidationResult, IConfigurationManager } from './types';

module.exports = {
  ConfigurationManager,
  configManager,
  ConfigurationSchema
};