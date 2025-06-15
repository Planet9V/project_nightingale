/**
 * Document Extraction Types for Project Seldon
 * Handles PDF, MD, TXT and other document formats extraction
 */

import { ETLContext, PipelineError, DocumentFormat } from './etl';

export interface ExtractionConfig {
  supportedFormats: string[];
  maxFileSize: number; // bytes
  encoding: string;
  ocrEnabled: boolean;
  languageDetection: boolean;
  preserveFormatting: boolean;
  extractMetadata: boolean;
  extractImages: boolean;
  extractTables: boolean;
}

export interface DocumentSource {
  id: string;
  type: SourceType;
  path: string;
  format: DocumentFormat;
  size: number;
  checksum: string;
  lastModified: Date;
  metadata: SourceMetadata;
}

export enum SourceType {
  S3 = 'S3',
  LOCAL = 'LOCAL',
  URL = 'URL',
  DATABASE = 'DATABASE',
  API = 'API'
}

export enum DocumentType {
  REPORT = 'REPORT',
  ADVISORY = 'ADVISORY',
  PLAYBOOK = 'PLAYBOOK',
  PRESENTATION = 'PRESENTATION',
  EXECUTIVE_BRIEF = 'EXECUTIVE_BRIEF',
  TECHNICAL_DOCUMENT = 'TECHNICAL_DOCUMENT',
  OTHER = 'OTHER'
}

export interface SourceMetadata {
  bucket?: string;
  region?: string;
  contentType?: string;
  etag?: string;
  versionId?: string;
  tags?: Record<string, string>;
  customMetadata?: Record<string, any>;
}

export interface ExtractedDocument {
  id: string;
  sourceId: string;
  format: DocumentFormat;
  content: DocumentContent;
  metadata: DocumentMetadata;
  structure: DocumentStructure;
  extractionTime: Date;
  extractionMethod: string;
  quality: ExtractionQuality;
  checksum?: string;
  status?: string;
  extractedAt?: Date;
  processingTime?: number;
  error?: string;
}

export interface DocumentContent {
  raw: string;
  cleaned: string;
  normalized: string;
  language: string;
  encoding: string;
  wordCount: number;
  characterCount: number;
  lineCount: number;
}

export interface DocumentMetadata {
  title?: string;
  author?: string;
  subject?: string;
  keywords?: string[];
  creationDate?: Date;
  modificationDate?: Date;
  producer?: string;
  pageCount?: number;
  customProperties?: Record<string, any>;
  category?: string;
  source?: string;
  createdAt?: Date;
}

export interface DocumentStructure {
  sections: Section[];
  headings: Heading[];
  paragraphs: Paragraph[];
  tables?: Table[];
  images?: Image[];
  lists?: List[];
  footnotes?: Footnote[];
}

export interface Section {
  id: string;
  title: string;
  level: number;
  startOffset: number;
  endOffset: number;
  content: string;
  children?: Section[];
}

export interface Heading {
  id: string;
  text: string;
  level: number; // h1=1, h2=2, etc.
  offset: number;
  pageNumber?: number;
}

export interface Paragraph {
  id: string;
  text: string;
  offset: number;
  length: number;
  pageNumber?: number;
  style?: TextStyle;
}

export interface TextStyle {
  fontFamily?: string;
  fontSize?: number;
  bold?: boolean;
  italic?: boolean;
  underline?: boolean;
  color?: string;
}

export interface Table {
  id: string;
  caption?: string;
  headers: string[];
  rows: string[][];
  offset: number;
  pageNumber?: number;
}

export interface Image {
  id: string;
  caption?: string;
  altText?: string;
  url?: string;
  base64?: string;
  mimeType: string;
  width?: number;
  height?: number;
  offset: number;
  pageNumber?: number;
}

export interface List {
  id: string;
  type: 'ordered' | 'unordered';
  items: ListItem[];
  offset: number;
  pageNumber?: number;
}

export interface ListItem {
  text: string;
  level: number;
  children?: ListItem[];
}

export interface Footnote {
  id: string;
  referenceId: string;
  text: string;
  offset: number;
  pageNumber?: number;
}

export interface ExtractionQuality {
  score: number; // 0-1
  confidence: number; // 0-1
  warnings: QualityWarning[];
  issues: QualityIssue[];
}

export interface QualityWarning {
  type: WarningType;
  message: string;
  location?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export enum WarningType {
  ENCODING_ISSUE = 'ENCODING_ISSUE',
  MISSING_METADATA = 'MISSING_METADATA',
  PARTIAL_EXTRACTION = 'PARTIAL_EXTRACTION',
  OCR_QUALITY = 'OCR_QUALITY',
  UNSUPPORTED_FEATURE = 'UNSUPPORTED_FEATURE'
}

export interface QualityIssue {
  type: IssueType;
  message: string;
  location?: string;
  pageNumber?: number;
  offset?: number;
}

export enum IssueType {
  CORRUPTED_DATA = 'CORRUPTED_DATA',
  MISSING_CONTENT = 'MISSING_CONTENT',
  INVALID_FORMAT = 'INVALID_FORMAT',
  EXTRACTION_FAILED = 'EXTRACTION_FAILED'
}

export interface ExtractionProcessor {
  extract(source: DocumentSource, config: ExtractionConfig, context: ETLContext): Promise<ExtractedDocument>;
  validate(source: DocumentSource): Promise<boolean>;
  detectFormat(source: DocumentSource): Promise<DocumentFormat>;
  preprocess(source: DocumentSource): Promise<DocumentSource>;
}

export interface PDFExtractor extends ExtractionProcessor {
  extractText(source: DocumentSource): Promise<string>;
  extractMetadata(source: DocumentSource): Promise<DocumentMetadata>;
  extractStructure(source: DocumentSource): Promise<DocumentStructure>;
  extractImages(source: DocumentSource): Promise<Image[]>;
  extractTables(source: DocumentSource): Promise<Table[]>;
}

export interface MarkdownExtractor extends ExtractionProcessor {
  parseMarkdown(content: string): Promise<DocumentStructure>;
  extractFrontMatter(content: string): Promise<Record<string, any>>;
  extractCodeBlocks(content: string): Promise<CodeBlock[]>;
  extractLinks(content: string): Promise<Link[]>;
}

export interface CodeBlock {
  id: string;
  language?: string;
  code: string;
  offset: number;
  lineNumber: number;
}

export interface Link {
  text: string;
  url: string;
  title?: string;
  offset: number;
}

export interface ExtractionResult {
  document: ExtractedDocument;
  duration: number;
  memoryUsage: number;
  warnings: QualityWarning[];
  metrics: ExtractionMetrics;
}

export interface ExtractionMetrics {
  extractionTime: number;
  preprocessingTime: number;
  validationTime: number;
  contentSize: number;
  compressionRatio: number;
  extractionRate: number; // bytes/second
}

export interface ExtractionError extends PipelineError {
  source: DocumentSource;
  stage: 'preprocessing' | 'extraction' | 'validation' | 'postprocessing';
  recoverable: boolean;
}

export interface BatchExtractionRequest {
  sources: DocumentSource[];
  config: ExtractionConfig;
  parallel: boolean;
  continueOnError: boolean;
}

export interface BatchExtractionResult {
  successful: ExtractionResult[];
  failed: ExtractionError[];
  totalDuration: number;
  successRate: number;
}

// Extractor interfaces
export interface ContentExtractor {
  extract(source: DocumentSource, options?: ExtractionOptions): Promise<DocumentContent>;
  supports(format: DocumentFormat): boolean;
}

export interface MetadataExtractor {
  extract(source: DocumentSource): Promise<DocumentMetadata>;
  supports(format: DocumentFormat): boolean;
}

export interface ExtractionOptions {
  preserveFormatting?: boolean;
  extractTables?: boolean;
  extractImages?: boolean;
  ocrEnabled?: boolean;
  language?: string;
}

export interface ExtractionResult {
  document: ExtractedDocument;
  errors?: PipelineError[];
  warnings?: string[];
}
