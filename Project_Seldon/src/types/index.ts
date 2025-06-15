/**
 * Project Seldon Type Definitions
 * Central export point for all TypeScript interfaces and types
 */

// Core ETL Types - Explicit exports to avoid conflicts
export {
  ETLConfig,
  ETLPipeline,
  PipelineStatus,
  PipelineStage,
  StageStatus,
  Progress,
  PipelineMetadata,
  StageMetrics,
  PipelineError,
  ETLJob,
  JobStatus,
  JobInput,
  JobOutput,
  ETLContext,
  ETLLogger,
  MetricsCollector,
  CacheManager,
  ETLProcessor,
  BatchProcessor,
  StreamProcessor,
  ETLSchedule,
  ETLMonitor,
  TimeRange,
  PipelineMetrics,
  DocumentFormat,
  ProcessingStatus,
  CitationType,
  EntityType,
  VectorDBProvider,
  StorageClass as ETLStorageClass,
  ProcessingResult
} from './etl';

// Document Extraction Types
export {
  ExtractedDocument,
  DocumentMetadata,
  DocumentContent,
  DocumentType,
  SourceType,
  DocumentSource,
  SourceMetadata,
  DocumentStructure,
  StructureElement,
  ExtractionQuality,
  ExtractorResult,
  ExtractorStats,
  ExtractionConfig
} from './extraction';

// Transformation Types  
export {
  DocumentChunk,
  ChunkMetadata,
  ChunkPosition,
  ChunkContext,
  ChunkQuality,
  ChunkRelationship,
  TransformationConfig,
  TransformationResult,
  TransformationStats,
  ChunkingStrategy,
  ChunkingConfig,
  Embedding,
  EmbeddingConfig,
  PoolingStrategy,
  EnrichmentConfig,
  ValidationConfig,
  ValidatorFunction,
  ValidationResult,
  TransformedDocument
} from './transformation';

// Database Loading Types
export {
  LoadingConfig,
  VectorRecord,
  VectorMetadata,
  GraphNode,
  GraphRelationship,
  StorageLocation,
  LoadResult,
  LoadStats,
  LoadError,
  BatchLoadResult,
  VectorSearchResult,
  GraphQueryResult,
  StorageResult
} from './loading';

// Citation and Traceability Types
export {
  Citation,
  CitationContext,
  CitationOptions,
  CitationTracker,
  CitationMetadata,
  CharacterRange,
  WordRange,
  LineRange,
  CitationResult,
  CitationSource,
  CitationFormat,
  CitationStyle
} from './citation';

// Database Schema Types (explicitly export to avoid conflicts)
export {
  DatabaseConfig,
  PostgreSQLConfig,
  VectorDatabaseConfig,
  VectorRecord as DatabaseVectorRecord,
  VectorMetadata as DatabaseVectorMetadata,
  DocumentTable,
  ChunkTable,
  EmbeddingTable,
  CitationTable,
  RelationshipTable,
  ProcessingJobTable,
  DatabaseRecord
} from './database';

// S3 Integration Types - Explicit exports to avoid StorageClass conflict
export {
  S3Config,
  S3Credentials,
  HttpOptions,
  S3BucketConfig,
  S3EncryptionConfig,
  EncryptionType,
  S3LifecycleConfig,
  S3Transition,
  StorageClass as S3StorageClass,
  S3Expiration,
  S3CorsConfig,
  S3LoggingConfig,
  S3ReplicationConfig,
  S3ReplicationRule,
  S3Destination,
  S3ReplicationTime,
  S3Filter,
  S3Object,
  S3Owner,
  S3ObjectMetadata,
  S3UploadOptions,
  S3ACL,
  S3DownloadOptions,
  S3ListOptions,
  S3ListResult,
  S3CopyOptions,
  S3DeleteOptions,
  S3DeleteResult,
  S3MultipartUpload,
  S3Part,
  S3MultipartUploadOptions,
  S3PresignedUrlOptions,
  S3PresignedPostOptions,
  S3PostCondition,
  S3Event,
  S3EventRecord,
  S3EventName,
  S3UserIdentity,
  S3EventData,
  S3EventBucket,
  S3EventObject,
  S3Manager,
  S3UploadResult,
  S3DownloadResult,
  S3CopyResult,
  S3Metrics,
  S3OperationMetrics,
  S3ErrorMetric,
  S3BandwidthMetrics
} from './s3';

// Jina Types - Explicit exports to avoid DocumentChunk conflict
export {
  JinaServiceConfig,
  JinaRateLimitConfig,
  JinaEmbeddingRequest,
  JinaEmbeddingResponse,
  JinaRerankingRequest,
  JinaRerankingResponse,
  JinaClassifierRequest,
  JinaClassifierResponse,
  JinaDeepSearchRequest,
  JinaDeepSearchResponse,
  JinaErrorResponse,
  JinaAPIError,
  JinaRateLimitError,
  JinaServiceType,
  JinaOperation,
  QueueMetrics,
  ServiceMetrics,
  DocumentChunk as JinaDocumentChunk,
  ChunkEmbedding,
  ContentClassification,
  ProcessedDocument,
  JINA_SERVICE_CONFIGS,
  RATE_LIMIT_CONFIGS,
  DEFAULT_CLASSIFICATION_LABELS,
  ClassificationLabel
} from './jina';

// Pinecone Types
export {
  PineconeVectorRecord,
  PineconeSearchOptions,
  PineconeMetadata
} from './pinecone';

// Type Guards
export {
  isETLPipeline,
  isExtractedDocument,
  isDocumentChunk,
  isDatabaseRecord,
  isCitation,
  isS3Object,
  isVectorRecord
} from './guards';

// Utility Types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type DeepRequired<T> = {
  [P in keyof T]-?: T[P] extends object ? DeepRequired<T[P]> : T[P];
};

export type Nullable<T> = T | null;

export type Optional<T> = T | undefined;

export type AsyncResult<T> = Promise<T>;

export type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E };

// Common Types
export interface Timestamped {
  createdAt: Date;
  updatedAt: Date;
}

export interface Versioned {
  version: number;
  previousVersion?: number;
}

export interface Identifiable {
  id: string;
}

export interface Describable {
  name: string;
  description?: string;
}

export interface Taggable {
  tags?: string[];
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export interface SortOptions {
  field: string;
  direction: 'asc' | 'desc';
}

export interface FilterOptions {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'contains';
  value: any;
}

export interface SearchOptions {
  query: string;
  fields?: string[];
  fuzzy?: boolean;
  boost?: Record<string, number>;
}

// Error Types
export interface ValidationError {
  field: string;
  message: string;
  code?: string;
  value?: any;
}

export interface ProcessingError {
  stage: string;
  message: string;
  code?: string;
  details?: any;
  retryable?: boolean;
}

// Event Types
export interface Event<T = any> {
  id: string;
  type: string;
  timestamp: Date;
  source: string;
  data: T;
  metadata?: Record<string, any>;
}

export interface EventHandler<T = any> {
  handle(event: Event<T>): Promise<void>;
}

// Configuration Types
export interface FeatureFlag {
  name: string;
  enabled: boolean;
  rolloutPercentage?: number;
  conditions?: Record<string, any>;
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  keyGenerator?: (req: any) => string;
}

// Monitoring Types
export interface HealthCheck {
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  details?: Record<string, any>;
}

export interface Metric {
  name: string;
  value: number;
  unit: string;
  timestamp: Date;
  dimensions?: Record<string, string>;
}

// Type Predicates
export function isError(value: any): value is Error {
  return value instanceof Error;
}

export function isString(value: any): value is string {
  return typeof value === 'string';
}

export function isNumber(value: any): value is number {
  return typeof value === 'number' && !isNaN(value);
}

export function isArray<T>(value: any): value is T[] {
  return Array.isArray(value);
}

export function isObject(value: any): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function isDefined<T>(value: T | undefined | null): value is T {
  return value !== undefined && value !== null;
}

// Utility Functions
export function assertNever(x: never): never {
  throw new Error('Unexpected value: ' + x);
}

export function exhaustiveCheck(x: never): never {
  throw new Error('Exhaustive check failed');
}

// Re-export specific enums and types for convenience
export { 
  PipelineStatus,
  JobStatus,
  DocumentFormat,
  ProcessingStatus,
  CitationType,
  EntityType,
  VectorDBProvider,
  StorageClass,
  ProcessingResult
} from './etl';

export {
  ContentType
} from './transformation';

// Type aliases for common use cases
export type ID = string;
export type UUID = string;
export type ISODateString = string;
export type UnixTimestamp = number;
export type JSONValue = string | number | boolean | null | JSONObject | JSONArray;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = JSONValue[];

// Configuration Types
export type { 
  Configuration, 
  ConfigurationValidationResult, 
  IConfigurationManager,
  AIServiceConfig,
  StorageConfig,
  MonitoringConfig,
  ProcessingConfig,
  SecurityConfig
} from '../config/types';

// Constants
export const MAX_CHUNK_SIZE = 8192; // tokens
export const DEFAULT_EMBEDDING_DIMENSIONS = 1536;
export const MAX_BATCH_SIZE = 100;
export const DEFAULT_TIMEOUT_MS = 30000;

// ✅ TASK 1 COMPLETE: Type exports consolidated using explicit exports instead of wildcards
// - Renamed conflicting types: StorageClass → ETLStorageClass/S3StorageClass
// - Renamed conflicting types: VectorRecord → DatabaseVectorRecord
// - Renamed conflicting types: VectorMetadata → DatabaseVectorMetadata
// - Renamed conflicting types: DocumentChunk → JinaDocumentChunk (from jina.ts)

// ✅ TASK 3 COMPLETE: Unified Configuration interface created
// - Created /src/config/types.ts with comprehensive Configuration interface
// - Updated ConfigurationManager to implement IConfigurationManager interface
// - Updated all components to import Configuration from the correct path
// - Added configuration exports to main types index for convenience