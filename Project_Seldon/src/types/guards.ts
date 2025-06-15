/**
 * Type Guards for Project Seldon
 * Runtime type checking utilities
 */

import {
  ETLPipeline,
  ExtractedDocument,
  DocumentChunk,
  DatabaseRecord,
  Citation,
  S3Object,
  VectorRecord,
  PipelineStatus,
  DocumentFormat,
  ProcessingStatus,
  CitationType,
  RecordType
} from './index';

// ETL Type Guards
export function isETLPipeline(value: any): value is ETLPipeline {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.id === 'string' &&
    typeof value.name === 'string' &&
    typeof value.version === 'string' &&
    Object.values(PipelineStatus).includes(value.status) &&
    Array.isArray(value.stages) &&
    value.createdAt instanceof Date
  );
}

// Extraction Type Guards
export function isExtractedDocument(value: any): value is ExtractedDocument {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.id === 'string' &&
    typeof value.sourceId === 'string' &&
    Object.values(DocumentFormat).includes(value.format) &&
    value.content &&
    typeof value.content.raw === 'string' &&
    value.extractionTime instanceof Date
  );
}

// Transformation Type Guards
export function isDocumentChunk(value: any): value is DocumentChunk {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.id === 'string' &&
    typeof value.documentId === 'string' &&
    typeof value.content === 'string' &&
    value.metadata &&
    typeof value.metadata.tokenCount === 'number' &&
    value.position &&
    typeof value.position.index === 'number'
  );
}

// Database Type Guards
export function isDatabaseRecord(value: any): value is DatabaseRecord {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.id === 'string' &&
    Object.values(RecordType).includes(value.type) &&
    value.data &&
    typeof value.data === 'object' &&
    value.created_at instanceof Date
  );
}

// Citation Type Guards
export function isCitation(value: any): value is Citation {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.id === 'string' &&
    Object.values(CitationType).includes(value.type) &&
    value.source &&
    typeof value.source.documentId === 'string' &&
    typeof value.confidence === 'number' &&
    value.confidence >= 0 &&
    value.confidence <= 1
  );
}

// S3 Type Guards
export function isS3Object(value: any): value is S3Object {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.key === 'string' &&
    typeof value.bucket === 'string' &&
    typeof value.size === 'number' &&
    value.lastModified instanceof Date &&
    typeof value.etag === 'string'
  );
}

// Vector Type Guards
export function isVectorRecord(value: any): value is VectorRecord {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.id === 'string' &&
    Array.isArray(value.values) &&
    value.values.every((v: any) => typeof v === 'number') &&
    value.metadata &&
    typeof value.metadata === 'object'
  );
}

// Processing Status Guards
export function isProcessingStatus(value: any): value is ProcessingStatus {
  return Object.values(ProcessingStatus).includes(value as ProcessingStatus);
}

// Array Type Guards
export function isArrayOf<T>(
  value: any,
  guard: (item: any) => item is T
): value is T[] {
  return Array.isArray(value) && value.every(guard);
}

// Nullable Type Guards
export function isNullable<T>(
  value: any,
  guard: (item: any) => item is T
): value is T | null {
  return value === null || guard(value);
}

// Optional Type Guards
export function isOptional<T>(
  value: any,
  guard: (item: any) => item is T
): value is T | undefined {
  return value === undefined || guard(value);
}

// Partial Type Guards
export function hasRequiredFields<T extends Record<string, any>>(
  value: any,
  requiredFields: (keyof T)[]
): value is T {
  if (!value || typeof value !== 'object') {
    return false;
  }
  
  return requiredFields.every(field => field in value);
}

// Date Type Guards
export function isValidDate(value: any): value is Date {
  return value instanceof Date && !isNaN(value.getTime());
}

export function isISODateString(value: any): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  const date = new Date(value);
  return isValidDate(date) && date.toISOString() === value;
}

// Number Type Guards
export function isPositiveNumber(value: any): value is number {
  return typeof value === 'number' && value > 0 && !isNaN(value);
}

export function isInteger(value: any): value is number {
  return typeof value === 'number' && Number.isInteger(value);
}

export function isInRange(value: any, min: number, max: number): value is number {
  return typeof value === 'number' && value >= min && value <= max;
}

// String Type Guards
export function isNonEmptyString(value: any): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function isUUID(value: any): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(value);
}

export function isEmail(value: any): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value);
}

// Enum Type Guards
export function isEnumValue<T extends Record<string, any>>(
  value: any,
  enumObject: T
): value is T[keyof T] {
  return Object.values(enumObject).includes(value);
}

// Composite Type Guards
export function isValidChunk(chunk: any): chunk is DocumentChunk {
  return (
    isDocumentChunk(chunk) &&
    isNonEmptyString(chunk.content) &&
    chunk.metadata.tokenCount > 0 &&
    chunk.metadata.tokenCount <= 8192 && // MAX_CHUNK_SIZE
    (!chunk.embedding || isValidEmbedding(chunk.embedding))
  );
}

export function isValidEmbedding(embedding: any): boolean {
  return (
    embedding &&
    typeof embedding === 'object' &&
    Array.isArray(embedding.vector) &&
    embedding.vector.length === embedding.dimensions &&
    embedding.vector.every((v: any) => typeof v === 'number' && !isNaN(v)) &&
    isNonEmptyString(embedding.model) &&
    isValidDate(embedding.timestamp)
  );
}

// Error Type Guards
export function isError(value: any): value is Error {
  return value instanceof Error;
}

export function hasErrorShape(value: any): value is { message: string; code?: string } {
  return (
    value &&
    typeof value === 'object' &&
    typeof value.message === 'string'
  );
}

// Assertion Functions
export function assertDefined<T>(
  value: T | null | undefined,
  message?: string
): asserts value is T {
  if (value === null || value === undefined) {
    throw new Error(message || 'Value is null or undefined');
  }
}

export function assertType<T>(
  value: any,
  guard: (value: any) => value is T,
  message?: string
): asserts value is T {
  if (!guard(value)) {
    throw new Error(message || 'Type assertion failed');
  }
}

// Utility Type Guard Composers
export function createArrayGuard<T>(
  itemGuard: (item: any) => item is T
): (value: any) => value is T[] {
  return (value: any): value is T[] => isArrayOf(value, itemGuard);
}

export function createPartialGuard<T>(
  fullGuard: (value: any) => value is T,
  requiredFields: (keyof T)[]
): (value: any) => value is Partial<T> {
  return (value: any): value is Partial<T> => {
    if (!value || typeof value !== 'object') {
      return false;
    }
    return requiredFields.every(field => 
      !(field in value) || fullGuard({ ...value, [field]: value[field] })
    );
  };
}