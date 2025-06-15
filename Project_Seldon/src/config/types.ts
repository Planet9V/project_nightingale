/**
 * Unified Configuration Types for Project Seldon
 * Central configuration interface that consolidates all service configurations
 */

import { ETLConfig } from '../types/etl';
import { DatabaseConfig } from '../types/database';

/**
 * AI Service Configuration
 */
export interface AIServiceConfig {
  jina: JinaConfig;
  openai?: OpenAIConfig;
  anthropic?: AnthropicConfig;
}

export interface JinaConfig {
  apiKey: string;
  baseUrl: string;
  embeddingModel: string;
  rerankModel: string;
  classifierModel: string;
  maxTokens: number;
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
    burstLimit: number;
  };
}

export interface OpenAIConfig {
  apiKey: string;
  organization?: string;
  model: string;
  maxTokens: number;
}

export interface AnthropicConfig {
  apiKey: string;
  model: string;
  maxTokens: number;
}

/**
 * Storage Configuration
 */
export interface StorageConfig {
  local: LocalStorageConfig;
  s3?: S3StorageConfig;
  gcs?: GCSStorageConfig;
}

export interface LocalStorageConfig {
  tempDirectory: string;
  outputDirectory: string;
  maxFileSize: number;
}

export interface S3StorageConfig {
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  endpoint?: string;
}

export interface GCSStorageConfig {
  bucket: string;
  projectId: string;
  keyFilePath: string;
}

/**
 * Monitoring Configuration
 */
export interface MonitoringConfig {
  healthCheckInterval: number;
  metricsInterval: number;
  enablePrometheus: boolean;
  prometheusPort: number;
  logging: LoggingConfig;
}

export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  directory: string;
  maxFileSize: number;
  maxFiles: number;
  enableConsole: boolean;
  enableFile: boolean;
}

/**
 * Processing Configuration
 */
export interface ProcessingConfig {
  chunkSize: number;
  chunkOverlap: number;
  maxDocumentSize: number;
  supportedFormats: string[];
  enableOCR: boolean;
  ocrLanguages: string[];
}

/**
 * Security Configuration
 */
export interface SecurityConfig {
  encryption: {
    enabled: boolean;
    algorithm: string;
    keyRotationInterval: number;
  };
  authentication: {
    type: 'apiKey' | 'oauth' | 'jwt';
    tokenExpiry: number;
  };
  rateLimit: {
    enabled: boolean;
    windowMs: number;
    maxRequests: number;
  };
}

/**
 * Master Configuration Interface
 * This is the unified configuration type that all components should use
 */
export interface Configuration {
  environment: 'development' | 'staging' | 'production';
  etl: ETLConfig;
  databases: DatabaseConfig;
  ai: AIServiceConfig;
  storage: StorageConfig;
  monitoring: MonitoringConfig;
  processing?: ProcessingConfig;
  security?: SecurityConfig;
  
  // Feature flags
  features?: {
    enableCaching: boolean;
    enableAsyncProcessing: boolean;
    enableAutoScaling: boolean;
    enableDebugMode: boolean;
  };
  
  // API Configuration
  api?: {
    port: number;
    host: string;
    basePath: string;
    corsOrigins: string[];
    timeout: number;
  };
}

/**
 * Configuration validation result
 */
export interface ConfigurationValidationResult {
  valid: boolean;
  errors: ConfigurationError[];
  warnings: ConfigurationWarning[];
}

export interface ConfigurationError {
  path: string;
  message: string;
  value?: any;
}

export interface ConfigurationWarning {
  path: string;
  message: string;
  suggestion?: string;
}

/**
 * Configuration source types
 */
export type ConfigurationSource = 
  | 'environment'
  | 'file'
  | 'database'
  | 'remote'
  | 'default';

/**
 * Configuration metadata
 */
export interface ConfigurationMetadata {
  version: string;
  loadedAt: Date;
  sources: ConfigurationSource[];
  checksum?: string;
}

/**
 * Configuration manager interface
 */
export interface IConfigurationManager {
  load(): Promise<Configuration>;
  get(): Configuration;
  getValue<T>(path: string): T;
  validate(): Promise<ConfigurationValidationResult>;
  reload(): Promise<Configuration>;
  watch(callback: (config: Configuration) => void): void;
  unwatch(): void;
}

/**
 * Type guards for configuration
 */
export function isConfiguration(value: any): value is Configuration {
  return (
    typeof value === 'object' &&
    value !== null &&
    'environment' in value &&
    'etl' in value &&
    'databases' in value &&
    'ai' in value &&
    'storage' in value &&
    'monitoring' in value
  );
}

export function isProductionConfig(config: Configuration): boolean {
  return config.environment === 'production';
}

export function isDevelopmentConfig(config: Configuration): boolean {
  return config.environment === 'development';
}

/**
 * Default configuration values
 */
export const DEFAULT_CONFIGURATION: Partial<Configuration> = {
  environment: 'development',
  features: {
    enableCaching: true,
    enableAsyncProcessing: true,
    enableAutoScaling: false,
    enableDebugMode: false,
  },
  api: {
    port: 3000,
    host: 'localhost',
    basePath: '/api/v1',
    corsOrigins: ['http://localhost:3000'],
    timeout: 30000,
  },
};