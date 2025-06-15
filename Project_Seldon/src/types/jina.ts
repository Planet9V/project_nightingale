/**
 * Jina AI Service Types for Project Seldon
 * Generated: June 13, 2025
 * 
 * Comprehensive TypeScript interfaces for rate-limited Jina AI integration
 */

// ================================
// Core Configuration Types
// ================================

export interface JinaServiceConfig {
  embedding: {
    endpoint: string;
    model: string;
    rateLimit: number; // RPM
    dimensions: number;
  };
  reranking: {
    endpoint: string;
    model: string;
    rateLimit: number; // RPM
  };
  classifier: {
    endpoint: string;
    model: string;
    rateLimit: number; // RPM
  };
  deepSearch: {
    endpoint: string;
    model: string;
    rateLimit: number; // RPM
  };
}

export interface JinaRateLimitConfig {
  concurrency: number;
  intervalCap: number;
  interval: number; // milliseconds
}

// ================================
// Request/Response Types
// ================================

export interface JinaEmbeddingRequest {
  model: string;
  input: string | string[];
  dimensions?: number;
  encoding_format?: 'float' | 'base64';
  task?: string;
}

export interface JinaEmbeddingResponse {
  object: 'list';
  data: Array<{
    object: 'embedding';
    index: number;
    embedding: number[];
  }>;
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

export interface JinaRerankingRequest {
  model: string;
  query: string;
  documents: string[];
  top_k?: number;
  return_documents?: boolean;
}

export interface JinaRerankingResponse {
  object: 'list';
  data: Array<{
    index: number;
    relevance_score: number;
    document?: {
      text: string;
    };
  }>;
  model: string;
  usage: {
    total_tokens: number;
  };
}

export interface JinaClassifierRequest {
  model: string;
  input: string;
  labels: string[];
  multi_label?: boolean;
}

export interface JinaClassifierResponse {
  object: 'classification';
  prediction: string;
  scores: Array<{
    label: string;
    score: number;
  }>;
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

export interface JinaDeepSearchRequest {
  model: string;
  query: string;
  documents: string[];
  top_k?: number;
  search_depth?: 'basic' | 'advanced';
}

export interface JinaDeepSearchResponse {
  object: 'search_results';
  data: Array<{
    index: number;
    relevance_score: number;
    snippet: string;
    document: {
      text: string;
      metadata?: Record<string, any>;
    };
  }>;
  model: string;
  usage: {
    total_tokens: number;
  };
}

// ================================
// Error Types
// ================================

export interface JinaErrorResponse {
  error: {
    code: string;
    message: string;
    type: 'invalid_request_error' | 'rate_limit_error' | 'authentication_error' | 'api_error';
    param?: string;
  };
}

export class JinaAPIError extends Error {
  public readonly code: string;
  public readonly type: string;
  public readonly param?: string;

  constructor(errorResponse: JinaErrorResponse) {
    super(errorResponse.error.message);
    this.name = 'JinaAPIError';
    this.code = errorResponse.error.code;
    this.type = errorResponse.error.type;
    this.param = errorResponse.error.param;
  }
}

export class JinaRateLimitError extends Error {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number) {
    super(message);
    this.name = 'JinaRateLimitError';
    this.retryAfter = retryAfter;
  }
}

// ================================
// Service Operation Types
// ================================

export type JinaServiceType = 'embedding' | 'reranking' | 'classifier' | 'deepSearch';

export interface JinaOperation<T> {
  serviceType: JinaServiceType;
  operation: () => Promise<T>;
  priority?: number;
  retryCount?: number;
  metadata?: Record<string, any>;
}

export interface QueueMetrics {
  pending: number;
  running: number;
  completed: number;
  failed: number;
  totalProcessed: number;
  averageProcessingTime: number;
  rateLimitHits: number;
}

export interface ServiceMetrics {
  embedding: QueueMetrics;
  reranking: QueueMetrics;
  classifier: QueueMetrics;
  deepSearch: QueueMetrics;
}

// ================================
// ETL Integration Types
// ================================

export interface DocumentChunk {
  chunk_id: string;
  content: string;
  citation: {
    document_id: string;
    s3_key: string;
    section_index: number;
    paragraph_index: number;
    sentence_range: {
      start: number;
      end: number;
    };
    character_range: {
      start: number;
      end: number;
    };
  };
  token_count: number;
  chunk_index: number;
}

export interface ChunkEmbedding {
  chunk_id: string;
  embedding: number[];
  dimension_count: number;
  generated_at: string;
}

export interface ContentClassification {
  primary_label: string;
  confidence_scores: Array<{
    label: string;
    score: number;
  }>;
  classified_at: string;
}

export interface ProcessedDocument {
  chunks: DocumentChunk[];
  embeddings: ChunkEmbedding[];
  classification: ContentClassification;
  reranking_scores?: Array<{
    chunk_id: string;
    relevance_score: number;
  }>;
  search_results?: Array<{
    chunk_id: string;
    relevance_score: number;
    snippet: string;
  }>;
}

// ================================
// Configuration Constants
// ================================

export const JINA_SERVICE_CONFIGS: JinaServiceConfig = {
  embedding: {
    endpoint: 'https://api.jina.ai/v1/embeddings',
    model: 'jina-embeddings-v2-base-en',
    rateLimit: 2000, // RPM
    dimensions: 768
  },
  reranking: {
    endpoint: 'https://api.jina.ai/v1/rerank',
    model: 'jina-reranker-v1-base-en',
    rateLimit: 2000 // RPM
  },
  classifier: {
    endpoint: 'https://api.jina.ai/v1/classify',
    model: 'jina-classifier-v1-base-en',
    rateLimit: 60 // RPM - Much more restrictive
  },
  deepSearch: {
    endpoint: 'https://api.jina.ai/v1/search',
    model: 'jina-search-v1-base-en',
    rateLimit: 500 // RPM
  }
};

export const RATE_LIMIT_CONFIGS: Record<JinaServiceType, JinaRateLimitConfig> = {
  embedding: {
    concurrency: 10,
    intervalCap: 2000,
    interval: 60000 // 1 minute
  },
  reranking: {
    concurrency: 10,
    intervalCap: 2000,
    interval: 60000
  },
  classifier: {
    concurrency: 3,
    intervalCap: 60,
    interval: 60000
  },
  deepSearch: {
    concurrency: 5,
    intervalCap: 500,
    interval: 60000
  }
};

// ================================
// Default Classification Labels
// ================================

export const DEFAULT_CLASSIFICATION_LABELS = [
  'threat_intelligence',
  'vulnerability_report',
  'executive_summary',
  'technical_analysis',
  'incident_report',
  'compliance_document',
  'risk_assessment',
  'security_advisory',
  'penetration_test',
  'audit_report'
] as const;

export type ClassificationLabel = typeof DEFAULT_CLASSIFICATION_LABELS[number];