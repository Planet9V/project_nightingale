/**
 * Database Schema Types for Project Seldon
 * PostgreSQL and Vector Database schemas
 */

export interface DatabaseConfig {
  postgres: PostgreSQLConfig;
  vector: VectorDatabaseConfig;
  redis?: RedisConfig;
  monitoring: DatabaseMonitoringConfig;
  neo4j?: Neo4jConfig;
  pinecone?: PineconeConfig;
  supabase?: SupabaseConfig;
}

export interface Neo4jConfig {
  uri: string;
  username: string;
  password: string;
  database?: string;
  connectionTimeout?: number;
  maxConnectionPoolSize?: number;
}

export interface PineconeConfig {
  apiKey: string;
  environment: string;
  indexName: string;
  namespace?: string;
  topK?: number;
  includeMetadata?: boolean;
  includeValues?: boolean;
}

export interface SupabaseConfig {
  url: string;
  anonKey: string;
  serviceRoleKey?: string;
  database?: string;
  schema?: string;
}

export interface PostgreSQLConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean | SSLConfig;
  poolConfig: PoolConfig;
  schema: string;
}

export interface SSLConfig {
  rejectUnauthorized?: boolean;
  ca?: string;
  cert?: string;
  key?: string;
}

export interface PoolConfig {
  min: number;
  max: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
  acquireTimeoutMillis?: number;
  createTimeoutMillis?: number;
  destroyTimeoutMillis?: number;
  reapIntervalMillis?: number;
  createRetryIntervalMillis?: number;
}

export interface VectorDatabaseConfig {
  provider: VectorDBProvider;
  connectionString: string;
  apiKey?: string;
  environment?: string;
  options?: Record<string, any>;
}

export enum VectorDBProvider {
  PINECONE = 'PINECONE',
  WEAVIATE = 'WEAVIATE',
  QDRANT = 'QDRANT',
  PGVECTOR = 'PGVECTOR',
  CHROMA = 'CHROMA',
  MILVUS = 'MILVUS'
}

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  keyPrefix: string;
  ttl: number;
}

export interface DatabaseMonitoringConfig {
  enableMetrics: boolean;
  enableTracing: boolean;
  enableLogging: boolean;
  metricsPort?: number;
  tracingEndpoint?: string;
}

// Database Record Interface
export interface DatabaseRecord {
  id: string;
  created_at: Date;
  updated_at: Date;
  [key: string]: any;
}

// PostgreSQL Tables

export interface DocumentTable {
  id: string;
  source_id: string;
  s3_key: string;
  s3_bucket: string;
  format: string;
  size_bytes: bigint;
  checksum: string;
  title?: string;
  author?: string;
  description?: string;
  language: string;
  page_count?: number;
  word_count: number;
  extraction_metadata: Record<string, any>;
  processing_status: ProcessingStatus;
  error_message?: string;
  created_at: Date;
  updated_at: Date;
  processed_at?: Date;
  version: number;
}

export enum ProcessingStatus {
  PENDING = 'PENDING',
  EXTRACTING = 'EXTRACTING',
  TRANSFORMING = 'TRANSFORMING',
  EMBEDDING = 'EMBEDDING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  ARCHIVED = 'ARCHIVED'
}

export interface ChunkTable {
  id: string;
  document_id: string;
  chunk_index: number;
  content: string;
  content_hash: string;
  token_count: number;
  start_offset: number;
  end_offset: number;
  page_number?: number;
  section_title?: string;
  subsection_title?: string;
  chunk_metadata: ChunkMetadata;
  embedding_id?: string;
  quality_score: number;
  created_at: Date;
  updated_at: Date;
}

export interface ChunkMetadata {
  content_type: string;
  language: string;
  keywords?: string[];
  entities?: Record<string, any>[];
  custom?: Record<string, any>;
}

export interface EmbeddingTable {
  id: string;
  chunk_id: string;
  model: string;
  model_version: string;
  vector: number[];
  dimensions: number;
  normalized: boolean;
  generation_time_ms: number;
  created_at: Date;
}

export interface CitationTable {
  id: string;
  source_chunk_id: string;
  target_chunk_id?: string;
  citation_type: string;
  citation_text: string;
  confidence: number;
  verification_status: string;
  bibliographic_data?: Record<string, any>;
  location_data: LocationData;
  created_at: Date;
  updated_at: Date;
  verified_at?: Date;
  verified_by?: string;
}

export interface LocationData {
  start_offset: number;
  end_offset: number;
  page_number?: number;
  line_number?: number;
}

export interface RelationshipTable {
  id: string;
  source_entity_id: string;
  source_entity_type: string;
  target_entity_id: string;
  target_entity_type: string;
  relationship_type: string;
  strength: number;
  bidirectional: boolean;
  metadata?: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface ProcessingJobTable {
  id: string;
  pipeline_id: string;
  document_id?: string;
  job_type: string;
  status: string;
  input_config: Record<string, any>;
  output_summary?: Record<string, any>;
  error_details?: Record<string, any>;
  started_at: Date;
  completed_at?: Date;
  duration_ms?: number;
  created_by: string;
}

export interface AuditLogTable {
  id: string;
  entity_id: string;
  entity_type: string;
  operation: string;
  changes: Record<string, any>;
  user_id?: string;
  system_id: string;
  ip_address?: string;
  user_agent?: string;
  timestamp: Date;
}

// Vector Database Schemas

export interface VectorIndex {
  name: string;
  dimension: number;
  metric: string;
  pods?: number;
  replicas?: number;
  pod_type?: string;
  metadata_config?: MetadataConfig;
  source_collection?: string;
}

export interface MetadataConfig {
  indexed_fields: string[];
  stored_fields: string[];
  filterable_fields: FilterableField[];
}

export interface FilterableField {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'string[]';
  indexed: boolean;
}

export interface VectorRecord {
  id: string;
  values: number[];
  metadata: VectorMetadata;
  sparse_values?: SparseVector;
}

export interface VectorMetadata {
  chunk_id: string;
  document_id: string;
  content: string;
  title?: string;
  section?: string;
  page_number?: number;
  language: string;
  content_type: string;
  keywords?: string[];
  created_at: number; // timestamp
  [key: string]: any; // Allow custom metadata
}

export interface SparseVector {
  indices: number[];
  values: number[];
}

// Query Interfaces

export interface DatabaseQuery {
  select?: string[];
  from: string;
  where?: WhereClause;
  join?: JoinClause[];
  orderBy?: OrderByClause[];
  groupBy?: string[];
  having?: WhereClause;
  limit?: number;
  offset?: number;
}

export interface WhereClause {
  conditions: Condition[];
  operator: 'AND' | 'OR';
}

export interface Condition {
  field: string;
  operator: ComparisonOperator;
  value: any;
}

export enum ComparisonOperator {
  EQUALS = '=',
  NOT_EQUALS = '!=',
  GREATER_THAN = '>',
  LESS_THAN = '<',
  GREATER_THAN_OR_EQUALS = '>=',
  LESS_THAN_OR_EQUALS = '<=',
  LIKE = 'LIKE',
  IN = 'IN',
  NOT_IN = 'NOT IN',
  IS_NULL = 'IS NULL',
  IS_NOT_NULL = 'IS NOT NULL'
}

export interface JoinClause {
  type: JoinType;
  table: string;
  on: Condition;
}

export enum JoinType {
  INNER = 'INNER',
  LEFT = 'LEFT',
  RIGHT = 'RIGHT',
  FULL = 'FULL'
}

export interface OrderByClause {
  field: string;
  direction: 'ASC' | 'DESC';
}

// Migration Interfaces

export interface Migration {
  id: string;
  version: number;
  name: string;
  up: string; // SQL to apply migration
  down: string; // SQL to rollback migration
  checksum: string;
  applied_at?: Date;
}

export interface SchemaVersion {
  version: number;
  name: string;
  applied_at: Date;
  applied_by: string;
  execution_time_ms: number;
  checksum: string;
}

// Index Definitions

export interface IndexDefinition {
  name: string;
  table: string;
  columns: string[];
  unique: boolean;
  type?: IndexType;
  where?: string; // Partial index condition
  include?: string[]; // Covering index columns
  options?: Record<string, any>;
}

export enum IndexType {
  BTREE = 'btree',
  HASH = 'hash',
  GIST = 'gist',
  GIN = 'gin',
  BRIN = 'brin',
  IVFFLAT = 'ivfflat', // For pgvector
  HNSW = 'hnsw' // For pgvector
}

// Database Statistics

export interface TableStatistics {
  table_name: string;
  row_count: bigint;
  total_size_bytes: bigint;
  index_size_bytes: bigint;
  toast_size_bytes?: bigint;
  last_vacuum?: Date;
  last_analyze?: Date;
  dead_tuples?: bigint;
}

export interface IndexStatistics {
  index_name: string;
  table_name: string;
  size_bytes: bigint;
  number_of_scans: bigint;
  tuples_read: bigint;
  tuples_fetched: bigint;
  is_unique: boolean;
  is_primary: boolean;
}

export interface QueryStatistics {
  query_id: string;
  query_text: string;
  calls: bigint;
  total_time_ms: number;
  mean_time_ms: number;
  max_time_ms: number;
  rows_returned: bigint;
  cache_hits: bigint;
  cache_misses: bigint;
}