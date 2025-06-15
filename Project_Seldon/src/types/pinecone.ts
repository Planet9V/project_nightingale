/**
 * Pinecone-specific type definitions
 */

export interface PineconeVectorRecord {
  id: string;
  embedding: number[];
  documentId: string;
  chunkId: string;
  metadata: Record<string, any>;
  namespace?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface PineconeSearchOptions {
  query: number[];
  topK: number;
  filter?: Record<string, any>;
  includeValues?: boolean;
  includeMetadata?: boolean;
  namespace?: string;
  scoreThreshold?: number;
  limit?: number;
}

export interface PineconeMetadata {
  documentId: string;
  chunkId: string;
  chunkIndex?: number;
  fileType?: string;
  title?: string;
  createdAt?: string;
  updatedAt?: string;
  [key: string]: any;
}