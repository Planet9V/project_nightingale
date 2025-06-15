/**
 * Project Seldon Pipeline Exports
 * Central export point for all pipeline implementations
 */

export { ComprehensiveETLPipeline } from './ComprehensiveETLPipeline';
export { JinaEmbeddingPipeline } from './JinaEmbeddingPipeline';

// Pipeline interfaces and types
export interface PipelineOptions {
  batchSize?: number;
  maxRetries?: number;
  skipEmbeddings?: boolean;
  skipNeo4j?: boolean;
  skipS3?: boolean;
  dryRun?: boolean;
}

export interface PipelineResult {
  success: boolean;
  documentsProcessed: number;
  chunksCreated: number;
  embeddingsCreated: number;
  processingTime: number;
  errors?: string[];
}

export interface PipelineMetrics {
  startTime: Date;
  endTime?: Date;
  documentsTotal: number;
  documentsProcessed: number;
  documentsFailed: number;
  chunksTotal: number;
  embeddingsTotal: number;
  tokensUsed: number;
  averageProcessingTime: number;
}