/**
 * Core ETL Pipeline Types for Project Seldon
 * Defines the fundamental interfaces for the Extract, Transform, Load process
 */

export interface ETLConfig {
  environment: 'development' | 'staging' | 'production';
  batchSize: number;
  maxRetries: number;
  retryDelay: number;
  concurrency: number;
  timeout: number;
  enableMetrics: boolean;
  enableTracing: boolean;
}

export interface ETLPipeline {
  id: string;
  name: string;
  description: string;
  version: string;
  status: PipelineStatus;
  config: ETLConfig;
  stages: PipelineStage[];
  metadata: PipelineMetadata;
  createdAt: Date;
  updatedAt: Date;
}

export enum PipelineStatus {
  IDLE = 'IDLE',
  RUNNING = 'RUNNING',
  PAUSED = 'PAUSED',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED'
}

export interface PipelineStage {
  id: string;
  name: string;
  type: 'extract' | 'transform' | 'load';
  status: StageStatus;
  progress: Progress;
  startTime?: Date;
  endTime?: Date;
  error?: PipelineError;
  metrics?: StageMetrics;
}

export enum StageStatus {
  PENDING = 'PENDING',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  SKIPPED = 'SKIPPED'
}

export interface Progress {
  current: number;
  total: number;
  percentage: number;
  estimatedTimeRemaining?: number;
}

export interface PipelineMetadata {
  source: string;
  destination: string;
  tags: string[];
  owner: string;
  team: string;
  lastRunId?: string;
  scheduleExpression?: string;
}

export interface StageMetrics {
  itemsProcessed: number;
  itemsFailed: number;
  processingTime: number;
  averageItemTime: number;
  throughput: number;
  memoryUsage: number;
  cpuUsage: number;
}

export interface PipelineError {
  code: string;
  message: string;
  details?: any;
  stack?: string;
  timestamp: Date;
  retryable: boolean;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface ETLJob {
  id: string;
  pipelineId: string;
  status: JobStatus;
  input: JobInput;
  output?: JobOutput;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  error?: PipelineError;
  retryCount: number;
  metadata: Record<string, any>;
}

export enum JobStatus {
  QUEUED = 'QUEUED',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  RETRYING = 'RETRYING'
}

export interface JobInput {
  source: string;
  format: string;
  size: number;
  checksum: string;
  metadata: Record<string, any>;
}

export interface JobOutput {
  destination: string;
  format: string;
  size: number;
  checksum: string;
  recordsProcessed: number;
  metadata: Record<string, any>;
}

export interface ETLContext {
  jobId: string;
  pipelineId: string;
  stageId: string;
  config: ETLConfig;
  logger: ETLLogger;
  metrics: MetricsCollector;
  cache: CacheManager;
}

export interface ETLLogger {
  debug(message: string, context?: any): void;
  info(message: string, context?: any): void;
  warn(message: string, context?: any): void;
  error(message: string, error?: Error, context?: any): void;
}

export interface MetricsCollector {
  increment(metric: string, value?: number, tags?: Record<string, string>): void;
  gauge(metric: string, value: number, tags?: Record<string, string>): void;
  histogram(metric: string, value: number, tags?: Record<string, string>): void;
  timing(metric: string, value: number, tags?: Record<string, string>): void;
}

export interface CacheManager {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
}

export interface ETLProcessor<TInput, TOutput> {
  process(input: TInput, context: ETLContext): Promise<TOutput>;
  validate(input: TInput): Promise<boolean>;
  handleError(error: Error, input: TInput, context: ETLContext): Promise<void>;
}

export interface BatchProcessor<TInput, TOutput> extends ETLProcessor<TInput[], TOutput[]> {
  processBatch(items: TInput[], context: ETLContext): Promise<TOutput[]>;
  getBatchSize(): number;
}

export interface StreamProcessor<TInput, TOutput> extends ETLProcessor<TInput, TOutput> {
  processStream(stream: AsyncIterable<TInput>, context: ETLContext): AsyncIterable<TOutput>;
}

export interface ETLSchedule {
  id: string;
  pipelineId: string;
  expression: string; // Cron expression
  enabled: boolean;
  timezone: string;
  nextRunTime: Date;
  lastRunTime?: Date;
  metadata: Record<string, any>;
}

export interface ETLMonitor {
  getPipelineStatus(pipelineId: string): Promise<PipelineStatus>;
  getJobStatus(jobId: string): Promise<JobStatus>;
  getMetrics(pipelineId: string, timeRange: TimeRange): Promise<PipelineMetrics>;
  getErrors(pipelineId: string, timeRange: TimeRange): Promise<PipelineError[]>;
}

export interface TimeRange {
  start: Date;
  end: Date;
}

export interface PipelineMetrics {
  totalJobs: number;
  successfulJobs: number;
  failedJobs: number;
  averageDuration: number;
  throughput: number;
  errorRate: number;
}

// Additional enums that were missing
export enum DocumentFormat {
  PDF = 'PDF',
  EXCEL = 'EXCEL',
  CSV = 'CSV',
  JSON = 'JSON',
  XML = 'XML',
  TXT = 'TXT',
  MARKDOWN = 'MARKDOWN',
  HTML = 'HTML',
  DOCX = 'DOCX',
  IMAGE = 'IMAGE'
}

export enum ProcessingStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  SKIPPED = 'SKIPPED'
}

export enum CitationType {
  DOCUMENT = 'DOCUMENT',
  CHAPTER = 'CHAPTER',
  SECTION = 'SECTION',
  PARAGRAPH = 'PARAGRAPH',
  SENTENCE = 'SENTENCE',
  PHRASE = 'PHRASE'
}

export enum EntityType {
  ORGANIZATION = 'ORGANIZATION',
  PERSON = 'PERSON',
  LOCATION = 'LOCATION',
  TECHNOLOGY = 'TECHNOLOGY',
  VULNERABILITY = 'VULNERABILITY',
  THREAT_ACTOR = 'THREAT_ACTOR',
  DATE = 'DATE',
  EVENT = 'EVENT'
}

export enum VectorDBProvider {
  PINECONE = 'PINECONE',
  WEAVIATE = 'WEAVIATE',
  QDRANT = 'QDRANT',
  MILVUS = 'MILVUS',
  CHROMA = 'CHROMA'
}

export enum StorageClass {
  STANDARD = 'STANDARD',
  STANDARD_IA = 'STANDARD_IA',
  GLACIER = 'GLACIER',
  DEEP_ARCHIVE = 'DEEP_ARCHIVE',
  INTELLIGENT_TIERING = 'INTELLIGENT_TIERING'
}

// Processing result type for ETL operations
export interface ProcessingResult {
  success: boolean;
  documentsProcessed: number;
  documentsTotal: number;
  errors: PipelineError[];
  warnings: string[];
  startTime: Date;
  endTime: Date;
  duration: number;
  metadata: Record<string, any>;
}