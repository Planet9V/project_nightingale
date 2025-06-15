/**
 * Database Loading Types for Project Seldon
 * Handles loading transformed data into PostgreSQL and vector databases
 */

import { DocumentChunk, TransformedDocument } from './transformation';
import { ETLContext, PipelineError } from './etl';
import { VectorRecord, VectorMetadata } from './database';

export interface LoadingConfig {
  postgres: PostgresConfig;
  vector: VectorDBConfig;
  batch: BatchConfig;
  parallel: ParallelConfig;
  retry: RetryConfig;
  validation: LoadValidationConfig;
}

export interface PostgresConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  schema: string;
  poolSize: number;
  connectionTimeout: number;
  idleTimeout: number;
  ssl?: SSLConfig;
}

export interface SSLConfig {
  rejectUnauthorized: boolean;
  ca?: string;
  cert?: string;
  key?: string;
}

export interface VectorDBConfig {
  type: VectorDBType;
  endpoint: string;
  apiKey?: string;
  namespace?: string;
  indexName: string;
  dimensions: number;
  metric: DistanceMetric;
  replicas: number;
  shards: number;
}

export enum VectorDBType {
  PINECONE = 'PINECONE',
  WEAVIATE = 'WEAVIATE',
  QDRANT = 'QDRANT',
  MILVUS = 'MILVUS',
  CHROMA = 'CHROMA',
  PGVECTOR = 'PGVECTOR'
}

export enum DistanceMetric {
  COSINE = 'COSINE',
  EUCLIDEAN = 'EUCLIDEAN',
  DOT_PRODUCT = 'DOT_PRODUCT',
  MANHATTAN = 'MANHATTAN'
}

export interface BatchConfig {
  size: number;
  flushInterval: number; // ms
  maxRetries: number;
  retryDelay: number; // ms
  continueOnError: boolean;
}

export interface ParallelConfig {
  workers: number;
  queueSize: number;
  strategy: ParallelStrategy;
}

export enum ParallelStrategy {
  ROUND_ROBIN = 'ROUND_ROBIN',
  LEAST_LOADED = 'LEAST_LOADED',
  HASH_BASED = 'HASH_BASED'
}

export interface RetryConfig {
  maxAttempts: number;
  backoff: BackoffStrategy;
  initialDelay: number;
  maxDelay: number;
  retryableErrors: string[];
}

export enum BackoffStrategy {
  LINEAR = 'LINEAR',
  EXPONENTIAL = 'EXPONENTIAL',
  FIBONACCI = 'FIBONACCI',
  CONSTANT = 'CONSTANT'
}

export interface LoadValidationConfig {
  validateSchema: boolean;
  validateConstraints: boolean;
  validateReferences: boolean;
  checkDuplicates: boolean;
  customValidators?: LoadValidator[];
}

export type LoadValidator = (record: DatabaseRecord) => Promise<ValidationResult>;

export interface ValidationResult {
  valid: boolean;
  errors?: ValidationError[];
}

export interface ValidationError {
  field: string;
  value: any;
  constraint: string;
  message: string;
}

export interface DatabaseRecord {
  id: string;
  type: RecordType;
  data: Record<string, any>;
  metadata: RecordMetadata;
  created_at: Date;
  updated_at: Date;
}

export enum RecordType {
  DOCUMENT = 'DOCUMENT',
  CHUNK = 'CHUNK',
  EMBEDDING = 'EMBEDDING',
  CITATION = 'CITATION',
  RELATIONSHIP = 'RELATIONSHIP',
  METADATA = 'METADATA'
}

export interface RecordMetadata {
  source_id: string;
  version: number;
  checksum: string;
  tags?: string[];
  custom?: Record<string, any>;
}

export interface LoadingProcessor {
  load(documents: TransformedDocument[], config: LoadingConfig, context: ETLContext): Promise<LoadingResult>;
  loadBatch(records: DatabaseRecord[], config: BatchConfig): Promise<BatchResult>;
  validate(records: DatabaseRecord[], config: LoadValidationConfig): Promise<ValidationResult[]>;
  rollback(transactionId: string): Promise<void>;
}

export interface PostgresLoader extends LoadingProcessor {
  createSchema(): Promise<void>;
  loadDocuments(documents: TransformedDocument[]): Promise<string[]>;
  loadChunks(chunks: DocumentChunk[]): Promise<string[]>;
  loadCitations(citations: Citation[]): Promise<string[]>;
  createIndexes(): Promise<void>;
  vacuum(): Promise<void>;
}

export interface VectorLoader extends LoadingProcessor {
  createIndex(config: VectorIndexConfig): Promise<void>;
  upsertVectors(vectors: VectorRecord[]): Promise<string[]>;
  deleteVectors(ids: string[]): Promise<void>;
  queryVectors(query: VectorQuery): Promise<VectorSearchResult[]>;
  updateMetadata(id: string, metadata: Record<string, any>): Promise<void>;
}

export interface VectorIndexConfig {
  name: string;
  dimensions: number;
  metric: DistanceMetric;
  capacity: number;
  m?: number; // HNSW parameter
  efConstruction?: number; // HNSW parameter
  efSearch?: number; // HNSW parameter
}


export interface VectorQuery {
  vector: number[];
  topK: number;
  filter?: Record<string, any>;
  includeMetadata: boolean;
  includeVector: boolean;
  namespace?: string;
}

export interface VectorSearchResult {
  id: string;
  score: number;
  vector?: number[];
  metadata?: Record<string, any>;
}

export interface Citation {
  id: string;
  source_chunk_id: string;
  target_chunk_id: string;
  type: CitationType;
  confidence: number;
  context: string;
  metadata?: Record<string, any>;
}

export enum CitationType {
  DIRECT_QUOTE = 'DIRECT_QUOTE',
  PARAPHRASE = 'PARAPHRASE',
  REFERENCE = 'REFERENCE',
  FOOTNOTE = 'FOOTNOTE',
  BIBLIOGRAPHY = 'BIBLIOGRAPHY'
}

export interface LoadingResult {
  success: boolean;
  recordsLoaded: number;
  recordsFailed: number;
  duration: number;
  errors?: LoadingError[];
  statistics: LoadingStatistics;
}

export interface BatchResult {
  batchId: string;
  success: boolean;
  recordsProcessed: number;
  recordsFailed: number;
  errors?: LoadingError[];
}

export interface LoadingError extends PipelineError {
  recordId: string;
  recordType: RecordType;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  constraint?: string;
}

export interface LoadingStatistics {
  documentsLoaded: number;
  chunksLoaded: number;
  embeddingsLoaded: number;
  citationsLoaded: number;
  avgLoadTime: number;
  totalSize: number;
  compressionRatio: number;
}

export interface Transaction {
  id: string;
  status: TransactionStatus;
  operations: TransactionOperation[];
  startTime: Date;
  endTime?: Date;
  metadata: Record<string, any>;
}

export enum TransactionStatus {
  PENDING = 'PENDING',
  IN_PROGRESS = 'IN_PROGRESS',
  COMMITTED = 'COMMITTED',
  ROLLED_BACK = 'ROLLED_BACK',
  FAILED = 'FAILED'
}

export interface TransactionOperation {
  type: 'INSERT' | 'UPDATE' | 'DELETE';
  table: string;
  recordId: string;
  data?: Record<string, any>;
  timestamp: Date;
}

export interface DatabaseSchema {
  tables: TableSchema[];
  indexes: IndexSchema[];
  constraints: ConstraintSchema[];
  triggers: TriggerSchema[];
}

export interface TableSchema {
  name: string;
  columns: ColumnSchema[];
  primaryKey: string[];
  foreignKeys?: ForeignKeySchema[];
}

export interface ColumnSchema {
  name: string;
  type: string;
  nullable: boolean;
  default?: any;
  unique?: boolean;
}

export interface IndexSchema {
  name: string;
  table: string;
  columns: string[];
  type: 'BTREE' | 'HASH' | 'GIN' | 'GIST' | 'IVFFLAT' | 'HNSW';
  unique: boolean;
}

export interface ConstraintSchema {
  name: string;
  table: string;
  type: 'PRIMARY' | 'FOREIGN' | 'UNIQUE' | 'CHECK';
  definition: string;
}

export interface ForeignKeySchema {
  columns: string[];
  referenceTable: string;
  referenceColumns: string[];
  onDelete?: 'CASCADE' | 'SET NULL' | 'RESTRICT';
  onUpdate?: 'CASCADE' | 'SET NULL' | 'RESTRICT';
}

export interface TriggerSchema {
  name: string;
  table: string;
  event: 'INSERT' | 'UPDATE' | 'DELETE';
  timing: 'BEFORE' | 'AFTER';
  function: string;
}

export interface LoadingMetrics {
  insertRate: number; // records/second
  throughput: number; // MB/second
  latency: number; // ms
  errorRate: number; // percentage
  queueDepth: number;
  activeConnections: number;
}