/**
 * Citation and Traceability Types for Project Seldon
 * Ensures full audit trail and source attribution
 */

import { DocumentChunk } from './transformation';

export interface CitationConfig {
  enableAutoDetection: boolean;
  citationFormats: CitationFormat[];
  confidenceThreshold: number;
  maxCitationsPerChunk: number;
  crossReferenceDepth: number;
  includePageNumbers: boolean;
  includeLineNumbers: boolean;
}

export enum CitationFormat {
  APA = 'APA',
  MLA = 'MLA',
  CHICAGO = 'CHICAGO',
  IEEE = 'IEEE',
  HARVARD = 'HARVARD',
  CUSTOM = 'CUSTOM'
}

export interface Citation {
  id: string;
  type: CitationType;
  source: CitationSource;
  target: CitationTarget;
  confidence: number;
  verificationStatus: VerificationStatus;
  metadata: CitationMetadata;
  createdAt: Date;
  updatedAt: Date;
}

export enum CitationType {
  DIRECT_QUOTE = 'DIRECT_QUOTE',
  PARAPHRASE = 'PARAPHRASE',
  SUMMARY = 'SUMMARY',
  REFERENCE = 'REFERENCE',
  FOOTNOTE = 'FOOTNOTE',
  ENDNOTE = 'ENDNOTE',
  BIBLIOGRAPHY = 'BIBLIOGRAPHY',
  CROSS_REFERENCE = 'CROSS_REFERENCE'
}

export interface CitationSource {
  documentId: string;
  chunkId: string;
  text: string;
  location: SourceLocation;
  context: SourceContext;
}

export interface SourceLocation {
  startOffset: number;
  endOffset: number;
  pageNumber?: number;
  lineNumber?: number;
  sectionId?: string;
  paragraphId?: string;
}

export interface SourceContext {
  precedingText: string;
  followingText: string;
  sectionTitle?: string;
  chapterTitle?: string;
}

export interface CitationTarget {
  documentId: string;
  chunkId?: string;
  referenceId: string;
  referenceType: ReferenceType;
  bibliographicInfo?: BibliographicInfo;
}

export enum ReferenceType {
  DOCUMENT = 'DOCUMENT',
  ARTICLE = 'ARTICLE',
  BOOK = 'BOOK',
  WEBSITE = 'WEBSITE',
  REPORT = 'REPORT',
  STANDARD = 'STANDARD',
  PATENT = 'PATENT',
  CONFERENCE = 'CONFERENCE'
}

export interface BibliographicInfo {
  title: string;
  authors?: Author[];
  publicationDate?: Date;
  publisher?: string;
  journal?: string;
  volume?: string;
  issue?: string;
  pages?: string;
  doi?: string;
  isbn?: string;
  url?: string;
  accessDate?: Date;
}

export interface Author {
  firstName?: string;
  lastName: string;
  middleName?: string;
  orcid?: string;
  affiliation?: string;
}

export enum VerificationStatus {
  VERIFIED = 'VERIFIED',
  UNVERIFIED = 'UNVERIFIED',
  PARTIAL = 'PARTIAL',
  DISPUTED = 'DISPUTED',
  INVALID = 'INVALID'
}

export interface CitationMetadata {
  extractionMethod: string;
  extractionConfidence: number;
  verificationMethod?: string;
  verificationDate?: Date;
  verifiedBy?: string;
  tags?: string[];
  customMetadata?: Record<string, any>;
}

export interface CrossReference {
  id: string;
  sourceChunkId: string;
  targetChunkId: string;
  type: CrossReferenceType;
  bidirectional: boolean;
  strength: number; // 0-1
  context: CrossReferenceContext;
}

export enum CrossReferenceType {
  EXPLICIT = 'EXPLICIT', // "See section X"
  IMPLICIT = 'IMPLICIT', // Conceptual reference
  CONTINUATION = 'CONTINUATION', // Content continues
  ELABORATION = 'ELABORATION', // Expands on topic
  CONTRADICTION = 'CONTRADICTION', // Conflicts with
  SUPPORT = 'SUPPORT' // Supports claim
}

export interface CrossReferenceContext {
  sourceText: string;
  targetText: string;
  relationshipDescription: string;
  keywords: string[];
}

export interface TraceabilityRecord {
  id: string;
  entityId: string;
  entityType: EntityType;
  operation: OperationType;
  timestamp: Date;
  userId?: string;
  systemId: string;
  changes: ChangeRecord[];
  metadata: TraceabilityMetadata;
}

export enum EntityType {
  DOCUMENT = 'DOCUMENT',
  CHUNK = 'CHUNK',
  CITATION = 'CITATION',
  EMBEDDING = 'EMBEDDING',
  RELATIONSHIP = 'RELATIONSHIP'
}

export enum OperationType {
  CREATE = 'CREATE',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
  MERGE = 'MERGE',
  SPLIT = 'SPLIT',
  VERIFY = 'VERIFY',
  INVALIDATE = 'INVALIDATE'
}

export interface ChangeRecord {
  field: string;
  oldValue: any;
  newValue: any;
  reason?: string;
}

export interface TraceabilityMetadata {
  sourceSystem: string;
  processId: string;
  pipelineVersion: string;
  environment: string;
  tags?: string[];
}

export interface CitationChain {
  id: string;
  citations: Citation[];
  rootDocumentId: string;
  depth: number;
  branches: CitationBranch[];
  confidence: number;
}

export interface CitationBranch {
  id: string;
  parentCitationId?: string;
  citations: Citation[];
  branchType: BranchType;
}

export enum BranchType {
  PRIMARY = 'PRIMARY',
  SECONDARY = 'SECONDARY',
  TERTIARY = 'TERTIARY',
  SUPPORTING = 'SUPPORTING'
}

export interface CitationValidator {
  validate(citation: Citation): Promise<ValidationResult>;
  verifySource(source: CitationSource): Promise<boolean>;
  checkConsistency(citations: Citation[]): Promise<ConsistencyReport>;
  detectPlagiarism(text: string, citations: Citation[]): Promise<PlagiarismResult>;
}

export interface ValidationResult {
  valid: boolean;
  confidence: number;
  issues?: ValidationIssue[];
}

export interface ValidationIssue {
  type: IssueType;
  severity: IssueSeverity;
  message: string;
  field?: string;
}

export enum IssueType {
  MISSING_SOURCE = 'MISSING_SOURCE',
  INVALID_FORMAT = 'INVALID_FORMAT',
  BROKEN_REFERENCE = 'BROKEN_REFERENCE',
  DUPLICATE_CITATION = 'DUPLICATE_CITATION',
  CIRCULAR_REFERENCE = 'CIRCULAR_REFERENCE'
}

export enum IssueSeverity {
  ERROR = 'ERROR',
  WARNING = 'WARNING',
  INFO = 'INFO'
}

export interface ConsistencyReport {
  consistent: boolean;
  conflicts: ConflictRecord[];
  duplicates: DuplicateRecord[];
  gaps: GapRecord[];
}

export interface ConflictRecord {
  citationIds: string[];
  conflictType: string;
  description: string;
}

export interface DuplicateRecord {
  citationIds: string[];
  similarity: number;
}

export interface GapRecord {
  documentId: string;
  location: SourceLocation;
  expectedCitation: string;
}

export interface PlagiarismResult {
  isPlagiarized: boolean;
  similarity: number;
  matches: PlagiarismMatch[];
}

export interface PlagiarismMatch {
  text: string;
  sourceId: string;
  similarity: number;
  location: SourceLocation;
}

export interface CitationExtractor {
  extract(chunk: DocumentChunk): Promise<Citation[]>;
  detectFormat(text: string): CitationFormat;
  parseReference(text: string, format: CitationFormat): Promise<BibliographicInfo>;
  generateCitation(source: CitationSource, format: CitationFormat): string;
}

export interface CitationIndex {
  addCitation(citation: Citation): Promise<void>;
  getCitation(id: string): Promise<Citation | null>;
  findCitations(query: CitationQuery): Promise<Citation[]>;
  updateCitation(id: string, updates: Partial<Citation>): Promise<void>;
  deleteCitation(id: string): Promise<void>;
  rebuildIndex(): Promise<void>;
}

export interface CitationQuery {
  documentId?: string;
  chunkId?: string;
  type?: CitationType;
  verificationStatus?: VerificationStatus;
  confidenceMin?: number;
  dateRange?: DateRange;
  limit?: number;
  offset?: number;
}

export interface DateRange {
  start: Date;
  end: Date;
}

export interface CitationMetrics {
  totalCitations: number;
  verifiedCitations: number;
  averageConfidence: number;
  citationDensity: number; // citations per chunk
  crossReferenceRatio: number;
  verificationRate: number;
}