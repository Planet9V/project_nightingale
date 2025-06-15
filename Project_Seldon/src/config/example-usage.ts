/**
 * Example usage of the unified Configuration type
 * This demonstrates how components should use the new Configuration interface
 */

import { Configuration, ConfigurationValidationResult } from './types';
import { configManager } from './ConfigurationManager';
import { VectorDBProvider } from '../types/database';

// Example 1: Using configuration in a service
export class ExampleService {
  private config: Configuration;

  constructor(config: Configuration) {
    this.config = config;
  }

  async connectToDatabase() {
    // Access database configuration
    const { postgres, vector } = this.config.databases;
    
    console.log(`Connecting to PostgreSQL at ${postgres.host}:${postgres.port}`);
    console.log(`Using vector provider: ${vector.provider}`);
  }

  async processDocument(content: string) {
    // Access processing configuration
    const { chunkSize, chunkOverlap } = this.config.processing || {};
    
    // Access AI configuration
    const { jina } = this.config.ai;
    console.log(`Using Jina model: ${jina.embeddingModel}`);
  }
}

// Example 2: Loading and validating configuration
export async function initializeApplication() {
  try {
    // Load configuration
    const config = await configManager.load();
    
    // Validate configuration
    const validationResult: ConfigurationValidationResult = await configManager.validate();
    
    if (!validationResult.valid) {
      console.error('Configuration errors:', validationResult.errors);
      process.exit(1);
    }
    
    if (validationResult.warnings.length > 0) {
      console.warn('Configuration warnings:', validationResult.warnings);
    }
    
    // Create services with configuration
    const service = new ExampleService(config);
    await service.connectToDatabase();
    
    // Watch for configuration changes
    configManager.watch((newConfig) => {
      console.log('Configuration updated, reloading services...');
      // Handle configuration updates
    });
    
  } catch (error) {
    console.error('Failed to initialize application:', error);
    process.exit(1);
  }
}

// Example 3: Type-safe configuration access
export function getAIConfiguration(config: Configuration) {
  // TypeScript ensures we access valid properties
  const jinaConfig = config.ai.jina;
  const openAIConfig = config.ai.openai; // Optional, might be undefined
  
  // Environment-specific logic
  if (config.environment === 'production') {
    // Production-specific configuration
    if (!config.security?.encryption?.enabled) {
      throw new Error('Encryption must be enabled in production');
    }
  }
  
  return {
    jina: jinaConfig,
    openai: openAIConfig
  };
}

// Example 4: Creating a test configuration
export function createTestConfiguration(): Configuration {
  return {
    environment: 'development',
    etl: {
      environment: 'development',
      batchSize: 10,
      maxRetries: 3,
      retryDelay: 1000,
      concurrency: 2,
      timeout: 30000,
      enableMetrics: false,
      enableTracing: false
    },
    databases: {
      postgres: {
        host: 'localhost',
        port: 5432,
        database: 'test_db',
        user: 'test_user',
        password: 'test_password',
        poolConfig: {
          min: 1,
          max: 5,
          idleTimeoutMillis: 10000,
          connectionTimeoutMillis: 5000
        },
        schema: 'public'
      },
      vector: {
        provider: VectorDBProvider.PINECONE,
        connectionString: 'test-environment',
        apiKey: 'test-api-key',
        environment: 'test'
      },
      monitoring: {
        healthCheckInterval: 60000,
        metricsInterval: 30000,
        enablePrometheus: false,
        prometheusPort: 9090,
        logging: {
          level: 'debug',
          directory: './test-logs',
          maxFileSize: 1024 * 1024,
          maxFiles: 3,
          enableConsole: true,
          enableFile: false
        }
      }
    },
    ai: {
      jina: {
        apiKey: 'test-jina-key',
        baseUrl: 'https://api.jina.ai/v1',
        embeddingModel: 'jina-embeddings-v2-base-en',
        rerankModel: 'jina-reranker-v2-base-multilingual',
        classifierModel: 'jina-clip-v1',
        maxTokens: 8192,
        rateLimit: {
          requestsPerMinute: 10,
          requestsPerHour: 100,
          burstLimit: 5
        }
      }
    },
    storage: {
      local: {
        tempDirectory: '/tmp/test',
        outputDirectory: './test-output',
        maxFileSize: 10 * 1024 * 1024
      }
    },
    monitoring: {
      healthCheckInterval: 60000,
      metricsInterval: 30000,
      enablePrometheus: false,
      prometheusPort: 9090,
      logging: {
        level: 'debug',
        directory: './test-logs',
        maxFileSize: 1024 * 1024,
        maxFiles: 3,
        enableConsole: true,
        enableFile: false
      }
    }
  };
}