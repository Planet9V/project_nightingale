/**
 * Transformation Types for Project Seldon
 * Handles chunking, embedding, and document transformation
 */

import { ExtractedDocument, DocumentStructure } from './extraction';
import { ETLContext, PipelineError } from './etl';

export interface TransformationConfig {
  chunking: ChunkingConfig;
  embedding: EmbeddingConfig;
  enrichment: EnrichmentConfig;
  validation: ValidationConfig;
}

export interface ChunkingConfig {
  strategy: ChunkingStrategy;
  maxChunkSize: number; // tokens
  minChunkSize: number; // tokens
  overlap: number; // tokens
  preserveBoundaries: boolean;
  semanticChunking: boolean;
  customDelimiters?: string[];
}

export enum ChunkingStrategy {
  FIXED_SIZE = 'FIXED_SIZE',
  SEMANTIC = 'SEMANTIC',
  SENTENCE = 'SENTENCE',
  PARAGRAPH = 'PARAGRAPH',
  SECTION = 'SECTION',
  SLIDING_WINDOW = 'SLIDING_WINDOW',
  RECURSIVE = 'RECURSIVE',
  CUSTOM = 'CUSTOM'
}

export interface EmbeddingConfig {
  model: string;
  dimensions: number;
  batchSize: number;
  normalize: boolean;
  poolingStrategy: PoolingStrategy;
  contextWindow: number;
  includeMetadata: boolean;
}

export enum PoolingStrategy {
  MEAN = 'MEAN',
  MAX = 'MAX',
  CLS = 'CLS',
  WEIGHTED = 'WEIGHTED'
}

export interface EnrichmentConfig {
  extractEntities: boolean;
  extractKeywords: boolean;
  generateSummary: boolean;
  detectLanguage: boolean;
  analyzeSentiment: boolean;
  classifyContent: boolean;
  extractRelations: boolean;
}

export interface ValidationConfig {
  minContentLength: number;
  maxContentLength: number;
  requiredFields: string[];
  customValidators?: ValidatorFunction[];
}

export type ValidatorFunction = (chunk: DocumentChunk) => Promise<ValidationResult>;

export interface ValidationResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
}

export interface DocumentChunk {
  id: string;
  documentId: string;
  sourceId: string;
  content: string;
  metadata: ChunkMetadata;
  embedding?: Embedding;
  position: ChunkPosition;
  context: ChunkContext;
  relationships: ChunkRelationship[];
  quality: ChunkQuality;
}

export interface ChunkMetadata {
  title?: string;
  section?: string;
  subsection?: string;
  pageNumber?: number;
  paragraphNumber?: number;
  tokenCount: number;
  wordCount: number;
  language: string;
  contentType: ContentType;
  tags?: string[];
  customMetadata?: Record<string, any>;
}

export enum ContentType {
  TEXT = 'TEXT',
  CODE = 'CODE',
  TABLE = 'TABLE',
  LIST = 'LIST',
  HEADING = 'HEADING',
  QUOTE = 'QUOTE',
  MIXED = 'MIXED'
}

export interface Embedding {
  vector: number[];
  model: string;
  dimensions: number;
  normalized: boolean;
  timestamp: Date;
}

export interface ChunkPosition {
  index: number; // position in document
  startOffset: number; // character offset
  endOffset: number;
  startToken?: number; // token offset
  endToken?: number;
  level: number; // hierarchy level
}

export interface ChunkContext {
  preceding: string; // context before chunk
  following: string; // context after chunk
  parent?: string; // parent section/heading
  documentTitle: string;
  documentPath: string;
}

export interface ChunkRelationship {
  type: RelationshipType;
  targetId: string;
  strength: number; // 0-1
  metadata?: Record<string, any>;
}

export enum RelationshipType {
  NEXT = 'NEXT',
  PREVIOUS = 'PREVIOUS',
  PARENT = 'PARENT',
  CHILD = 'CHILD',
  REFERENCE = 'REFERENCE',
  SIMILAR = 'SIMILAR',
  CROSS_REFERENCE = 'CROSS_REFERENCE'
}

export interface ChunkQuality {
  score: number; // 0-1
  completeness: number; // 0-1
  coherence: number; // 0-1
  relevance: number; // 0-1
  uniqueness: number; // 0-1
}

export interface TransformationProcessor {
  transform(document: ExtractedDocument, config: TransformationConfig, context: ETLContext): Promise<TransformedDocument>;
  chunk(document: ExtractedDocument, config: ChunkingConfig): Promise<DocumentChunk[]>;
  embed(chunks: DocumentChunk[], config: EmbeddingConfig): Promise<DocumentChunk[]>;
  enrich(chunks: DocumentChunk[], config: EnrichmentConfig): Promise<DocumentChunk[]>;
}

export interface TransformedDocument {
  id: string;
  sourceDocument: ExtractedDocument;
  chunks: DocumentChunk[];
  metadata: TransformationMetadata;
  relationships: DocumentRelationship[];
  summary?: DocumentSummary;
  entities?: Entity[];
  keywords?: Keyword[];
}

export interface TransformationMetadata {
  transformationTime: Date;
  chunkCount: number;
  totalTokens: number;
  averageChunkSize: number;
  embeddingModel: string;
  transformationVersion: string;
}

export interface DocumentRelationship {
  sourceId: string;
  targetId: string;
  type: string;
  confidence: number;
  metadata?: Record<string, any>;
}

export interface DocumentSummary {
  text: string;
  length: number;
  method: string;
  keyPoints?: string[];
  abstractiveSummary?: string;
  extractiveSummary?: string;
}

export interface Entity {
  text: string;
  type: EntityType;
  confidence: number;
  offset: number;
  length: number;
  normalized?: string;
  metadata?: Record<string, any>;
}

export enum EntityType {
  PERSON = 'PERSON',
  ORGANIZATION = 'ORGANIZATION',
  LOCATION = 'LOCATION',
  DATE = 'DATE',
  TIME = 'TIME',
  MONEY = 'MONEY',
  PERCENTAGE = 'PERCENTAGE',
  PRODUCT = 'PRODUCT',
  EVENT = 'EVENT',
  CUSTOM = 'CUSTOM'
}

export interface Keyword {
  text: string;
  score: number;
  frequency: number;
  positions: number[];
  variants?: string[];
}

export interface ChunkingResult {
  chunks: DocumentChunk[];
  statistics: ChunkingStatistics;
  issues?: ChunkingIssue[];
}

export interface ChunkingStatistics {
  totalChunks: number;
  averageSize: number;
  minSize: number;
  maxSize: number;
  totalOverlap: number;
  distribution: Record<string, number>;
}

export interface ChunkingIssue {
  type: 'UNDERSIZED' | 'OVERSIZED' | 'BOUNDARY_SPLIT' | 'ORPHANED';
  chunkId: string;
  message: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface EmbeddingResult {
  chunks: DocumentChunk[];
  model: string;
  duration: number;
  tokensProcessed: number;
  errors?: EmbeddingError[];
}

export interface EmbeddingError extends PipelineError {
  chunkId: string;
  reason: string;
}

export interface SemanticChunker {
  identifyBoundaries(text: string, structure: DocumentStructure): Promise<number[]>;
  scoreCoherence(chunk: string): Promise<number>;
  optimizeChunkSize(chunks: string[], targetSize: number): Promise<string[]>;
}

export interface TextSplitter {
  split(text: string, config: ChunkingConfig): string[];
  merge(chunks: string[], maxSize: number): string[];
  overlap(chunks: string[], overlapSize: number): string[];
}

export interface TransformationMetrics {
  chunkingTime: number;
  embeddingTime: number;
  enrichmentTime: number;
  validationTime: number;
  totalTime: number;
  chunksPerSecond: number;
  tokensPerSecond: number;
}


export interface TransformationOptions {
  chunking?: ChunkingConfig;
  embedding?: EmbeddingOptions;
  enrichment?: EnrichmentConfig;
  validation?: ValidationConfig;
}

export interface EmbeddingOptions {
  model: string;
  dimensions?: number;
  batchSize?: number;
  normalize?: boolean;
}

export interface TokenizerOptions {
  model: string;
  maxTokens?: number;
  padding?: boolean;
  truncation?: boolean;
}

export interface TransformationResult {
  chunks: DocumentChunk[];
  metadata: TransformationMetadata;
  errors?: PipelineError[];
  warnings?: string[];
}
