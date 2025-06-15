import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  DeleteObjectCommand,
  CopyObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createReadStream, promises as fs } from 'fs';
import { createHash } from 'crypto';
import path from 'path';
import mime from 'mime-types';
import { logger } from '../utils/logger';
import { Readable } from 'stream';

export interface S3DocumentMetadata {
  documentId: string;
  originalPath: string;
  fileType: string;
  fileSize: number;
  hash: string;
  uploadedAt: string;
  contentType: string;
  processingStatus?: string;
  chunks?: number;
  embeddings?: number;
}

export interface S3UploadResult {
  bucket: string;
  key: string;
  etag: string;
  location: string;
  metadata: S3DocumentMetadata;
}

export interface S3Config {
  bucket: string;
  region: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  folders: {
    documents: string;
    embeddings: string;
    citations: string;
    metadata: string;
  };
}

export class S3DocumentManager {
  private s3Client: S3Client;
  private config: S3Config;

  constructor(config: S3Config) {
    this.config = config;
    
    // Initialize S3 client
    this.s3Client = new S3Client({
      region: config.region,
      ...(config.accessKeyId && config.secretAccessKey && {
        credentials: {
          accessKeyId: config.accessKeyId,
          secretAccessKey: config.secretAccessKey,
        },
      }),
    });
  }

  /**
   * Upload a document to S3 with proper organization
   */
  async uploadDocument(
    filePath: string,
    documentId: string,
    metadata?: Partial<S3DocumentMetadata>
  ): Promise<S3UploadResult> {
    try {
      // Read file and calculate hash
      const fileBuffer = await fs.readFile(filePath);
      const hash = createHash('sha256').update(fileBuffer).digest('hex');
      const stats = await fs.stat(filePath);
      
      // Determine file type and content type
      const fileExt = path.extname(filePath).toLowerCase();
      const fileName = path.basename(filePath);
      const contentType = mime.lookup(filePath) || 'application/octet-stream';
      
      // Organize by date and file type
      const date = new Date();
      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');
      
      // Create S3 key with proper folder structure
      const s3Key = `${this.config.folders.documents}${year}/${month}/${day}/${this.getFileTypeFolder(fileExt)}/${documentId}/${fileName}`;
      
      // Prepare metadata
      const fullMetadata: S3DocumentMetadata = {
        documentId,
        originalPath: filePath,
        fileType: fileExt.substring(1),
        fileSize: stats.size,
        hash,
        uploadedAt: new Date().toISOString(),
        contentType,
        ...metadata,
      };
      
      // Upload to S3
      const command = new PutObjectCommand({
        Bucket: this.config.bucket,
        Key: s3Key,
        Body: fileBuffer,
        ContentType: contentType,
        Metadata: this.serializeMetadata(fullMetadata),
        ServerSideEncryption: 'AES256',
        StorageClass: 'INTELLIGENT_TIERING',
      });
      
      const response = await this.s3Client.send(command);
      
      logger.info('Document uploaded to S3', {
        bucket: this.config.bucket,
        key: s3Key,
        size: stats.size,
        etag: response.ETag,
      });
      
      return {
        bucket: this.config.bucket,
        key: s3Key,
        etag: response.ETag || '',
        location: `s3://${this.config.bucket}/${s3Key}`,
        metadata: fullMetadata,
      };
      
    } catch (error) {
      logger.error('Failed to upload document to S3', {
        filePath,
        documentId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Upload document from buffer (for processed content)
   */
  async uploadBuffer(
    buffer: Buffer,
    key: string,
    contentType: string,
    metadata?: Record<string, string>
  ): Promise<S3UploadResult> {
    try {
      const hash = createHash('sha256').update(buffer).digest('hex');
      
      const command = new PutObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
        Body: buffer,
        ContentType: contentType,
        Metadata: metadata,
        ServerSideEncryption: 'AES256',
      });
      
      const response = await this.s3Client.send(command);
      
      return {
        bucket: this.config.bucket,
        key,
        etag: response.ETag || '',
        location: `s3://${this.config.bucket}/${key}`,
        metadata: {
          documentId: metadata?.documentId || '',
          originalPath: '',
          fileType: contentType,
          fileSize: buffer.length,
          hash,
          uploadedAt: new Date().toISOString(),
          contentType,
        },
      };
      
    } catch (error) {
      logger.error('Failed to upload buffer to S3', { key, error: error.message });
      throw error;
    }
  }

  /**
   * Get a presigned URL for direct access to a document
   */
  async getPresignedUrl(
    key: string,
    expiresIn: number = 3600 // 1 hour default
  ): Promise<string> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      
      const url = await getSignedUrl(this.s3Client, command, { expiresIn });
      
      return url;
    } catch (error) {
      logger.error('Failed to generate presigned URL', { key, error: error.message });
      throw error;
    }
  }

  /**
   * Download a document from S3
   */
  async downloadDocument(key: string): Promise<Buffer> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      
      const response = await this.s3Client.send(command);
      
      if (response.Body) {
        return Buffer.from(await this.streamToBuffer(response.Body as Readable));
      }
      
      throw new Error('No body in S3 response');
      
    } catch (error) {
      logger.error('Failed to download document from S3', { key, error: error.message });
      throw error;
    }
  }

  /**
   * Get document metadata
   */
  async getDocumentMetadata(key: string): Promise<S3DocumentMetadata | null> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      
      const response = await this.s3Client.send(command);
      
      if (response.Metadata) {
        return this.deserializeMetadata(response.Metadata);
      }
      
      return null;
      
    } catch (error) {
      logger.error('Failed to get document metadata', { key, error: error.message });
      return null;
    }
  }

  /**
   * List documents in a folder
   */
  async listDocuments(
    prefix: string,
    maxKeys: number = 1000
  ): Promise<Array<{ key: string; size: number; lastModified: Date }>> {
    try {
      const command = new ListObjectsV2Command({
        Bucket: this.config.bucket,
        Prefix: prefix,
        MaxKeys: maxKeys,
      });
      
      const response = await this.s3Client.send(command);
      
      return (response.Contents || []).map(obj => ({
        key: obj.Key || '',
        size: obj.Size || 0,
        lastModified: obj.LastModified || new Date(),
      }));
      
    } catch (error) {
      logger.error('Failed to list documents', { prefix, error: error.message });
      return [];
    }
  }

  /**
   * Store embeddings in S3
   */
  async storeEmbeddings(
    documentId: string,
    embeddings: number[][],
    metadata?: Record<string, string>
  ): Promise<string> {
    try {
      const key = `${this.config.folders.embeddings}${documentId}.json`;
      const content = JSON.stringify({
        documentId,
        embeddings,
        dimensions: embeddings[0]?.length || 0,
        count: embeddings.length,
        createdAt: new Date().toISOString(),
      });
      
      await this.uploadBuffer(
        Buffer.from(content),
        key,
        'application/json',
        {
          documentId,
          type: 'embeddings',
          count: String(embeddings.length),
          ...metadata,
        }
      );
      
      return key;
      
    } catch (error) {
      logger.error('Failed to store embeddings', { documentId, error: error.message });
      throw error;
    }
  }

  /**
   * Store citation data in S3
   */
  async storeCitations(
    documentId: string,
    citations: Array<{
      quote: string;
      startPosition: number;
      endPosition: number;
      chunkId: string;
    }>
  ): Promise<string> {
    try {
      const key = `${this.config.folders.citations}${documentId}.json`;
      const content = JSON.stringify({
        documentId,
        citations,
        count: citations.length,
        createdAt: new Date().toISOString(),
      });
      
      await this.uploadBuffer(
        Buffer.from(content),
        key,
        'application/json',
        {
          documentId,
          type: 'citations',
          count: String(citations.length),
        }
      );
      
      return key;
      
    } catch (error) {
      logger.error('Failed to store citations', { documentId, error: error.message });
      throw error;
    }
  }

  /**
   * Helper: Get folder based on file type
   */
  private getFileTypeFolder(extension: string): string {
    const typeMap: Record<string, string> = {
      '.pdf': 'pdf',
      '.doc': 'office',
      '.docx': 'office',
      '.xls': 'office',
      '.xlsx': 'office',
      '.ppt': 'office',
      '.pptx': 'office',
      '.md': 'markdown',
      '.txt': 'text',
      '.json': 'json',
      '.xml': 'xml',
      '.csv': 'data',
      '.png': 'images',
      '.jpg': 'images',
      '.jpeg': 'images',
      '.gif': 'images',
      '.bmp': 'images',
      '.svg': 'images',
    };
    
    return typeMap[extension.toLowerCase()] || 'other';
  }

  /**
   * Helper: Serialize metadata for S3
   */
  private serializeMetadata(metadata: S3DocumentMetadata): Record<string, string> {
    const result: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(metadata)) {
      if (value !== undefined && value !== null) {
        result[key] = String(value);
      }
    }
    
    return result;
  }

  /**
   * Helper: Deserialize metadata from S3
   */
  private deserializeMetadata(metadata: Record<string, string>): S3DocumentMetadata {
    return {
      documentId: metadata.documentId || '',
      originalPath: metadata.originalPath || '',
      fileType: metadata.fileType || '',
      fileSize: parseInt(metadata.fileSize || '0', 10),
      hash: metadata.hash || '',
      uploadedAt: metadata.uploadedAt || '',
      contentType: metadata.contentType || '',
      processingStatus: metadata.processingStatus,
      chunks: metadata.chunks ? parseInt(metadata.chunks, 10) : undefined,
      embeddings: metadata.embeddings ? parseInt(metadata.embeddings, 10) : undefined,
    };
  }

  /**
   * Helper: Convert stream to buffer
   */
  private async streamToBuffer(stream: Readable): Promise<Buffer> {
    const chunks: Buffer[] = [];
    
    return new Promise((resolve, reject) => {
      stream.on('data', chunk => chunks.push(Buffer.from(chunk)));
      stream.on('error', reject);
      stream.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  /**
   * Delete a document from S3
   */
  async deleteDocument(key: string): Promise<void> {
    try {
      const command = new DeleteObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      
      await this.s3Client.send(command);
      
      logger.info('Document deleted from S3', { key });
      
    } catch (error) {
      logger.error('Failed to delete document', { key, error: error.message });
      throw error;
    }
  }

  /**
   * Copy a document within S3
   */
  async copyDocument(sourceKey: string, destinationKey: string): Promise<void> {
    try {
      const command = new CopyObjectCommand({
        Bucket: this.config.bucket,
        CopySource: `${this.config.bucket}/${sourceKey}`,
        Key: destinationKey,
        ServerSideEncryption: 'AES256',
      });
      
      await this.s3Client.send(command);
      
      logger.info('Document copied in S3', { sourceKey, destinationKey });
      
    } catch (error) {
      logger.error('Failed to copy document', { sourceKey, destinationKey, error: error.message });
      throw error;
    }
  }
}