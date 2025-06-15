export interface TransformedDocument {
  id: string;
  title: string;
  authors: string[];
  publicationDate?: Date;
  abstract: string;
  keywords: string[];
  methodology?: string;
  keyFindings?: string;
  limitations?: string;
  futureWork?: string;
  chunks: TransformedChunk[];
  metadata: DocumentMetadata;
}

export interface TransformedChunk {
  id: string;
  index: number;
  content: string;
  embedding?: number[];
  citations: Citation[];
  metadata: ChunkMetadata;
}

export interface Citation {
  text: string;
  authors: string[];
  year?: number;
  title?: string;
  journal?: string;
  doi?: string;
  url?: string;
  type: 'direct' | 'indirect' | 'self';
  confidenceScore: number;
  metadata?: Record<string, any>;
}

export interface DocumentMetadata {
  collectionId: string;
  documentType: 'paper' | 'report' | 'article' | 'book' | 'thesis' | 'other';
  sourceUrl?: string;
  processingDate: Date;
  version?: string;
  tags?: string[];
  [key: string]: any;
}

export interface ChunkMetadata {
  sectionTitle?: string;
  chunkType: 'abstract' | 'introduction' | 'methodology' | 'results' | 'discussion' | 'conclusion' | 'references' | 'other';
  startPage?: number;
  endPage?: number;
  figures?: string[];
  tables?: string[];
  equations?: string[];
  [key: string]: any;
}