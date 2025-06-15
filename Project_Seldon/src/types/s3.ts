/**
 * S3 Integration Types for Project Seldon
 * Handles S3 bucket operations and document management
 */

export interface S3Config {
  region: string;
  credentials?: S3Credentials;
  endpoint?: string; // For S3-compatible services
  forcePathStyle?: boolean;
  signatureVersion?: string;
  sslEnabled?: boolean;
  maxRetries?: number;
  httpOptions?: HttpOptions;
}

export interface S3Credentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface HttpOptions {
  timeout?: number;
  xhrAsync?: boolean;
  xhrWithCredentials?: boolean;
}

export interface S3BucketConfig {
  name: string;
  region: string;
  versioning: boolean;
  encryption: S3EncryptionConfig;
  lifecycle: S3LifecycleConfig[];
  cors?: S3CorsConfig[];
  logging?: S3LoggingConfig;
  replication?: S3ReplicationConfig;
}

export interface S3EncryptionConfig {
  type: EncryptionType;
  kmsKeyId?: string;
  algorithm?: string;
}

export enum EncryptionType {
  SSE_S3 = 'AES256',
  SSE_KMS = 'aws:kms',
  SSE_C = 'customer-provided'
}

export interface S3LifecycleConfig {
  id: string;
  status: 'Enabled' | 'Disabled';
  prefix?: string;
  tags?: Record<string, string>;
  transitions: S3Transition[];
  expiration?: S3Expiration;
  noncurrentVersionExpiration?: number;
}

export interface S3Transition {
  days: number;
  storageClass: StorageClass;
}

export enum StorageClass {
  STANDARD = 'STANDARD',
  REDUCED_REDUNDANCY = 'REDUCED_REDUNDANCY',
  STANDARD_IA = 'STANDARD_IA',
  ONEZONE_IA = 'ONEZONE_IA',
  INTELLIGENT_TIERING = 'INTELLIGENT_TIERING',
  GLACIER = 'GLACIER',
  DEEP_ARCHIVE = 'DEEP_ARCHIVE'
}

export interface S3Expiration {
  days?: number;
  date?: Date;
  expiredObjectDeleteMarker?: boolean;
}

export interface S3CorsConfig {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
  maxAge?: number;
}

export interface S3LoggingConfig {
  targetBucket: string;
  targetPrefix: string;
}

export interface S3ReplicationConfig {
  role: string;
  rules: S3ReplicationRule[];
}

export interface S3ReplicationRule {
  id: string;
  priority?: number;
  status: 'Enabled' | 'Disabled';
  destination: S3Destination;
  filter?: S3Filter;
}

export interface S3Destination {
  bucket: string;
  storageClass?: StorageClass;
  replicationTime?: S3ReplicationTime;
  encryptionConfiguration?: S3EncryptionConfig;
}

export interface S3ReplicationTime {
  status: 'Enabled' | 'Disabled';
  time: number; // minutes
}

export interface S3Filter {
  prefix?: string;
  tags?: Record<string, string>;
}

// S3 Object Interfaces

export interface S3Object {
  key: string;
  bucket: string;
  size: number;
  lastModified: Date;
  etag: string;
  storageClass: StorageClass;
  owner?: S3Owner;
  metadata?: S3ObjectMetadata;
  versionId?: string;
}

export interface S3Owner {
  id: string;
  displayName?: string;
}

export interface S3ObjectMetadata {
  contentType?: string;
  contentEncoding?: string;
  contentLanguage?: string;
  contentDisposition?: string;
  cacheControl?: string;
  expires?: Date;
  websiteRedirectLocation?: string;
  serverSideEncryption?: string;
  sseCustomerAlgorithm?: string;
  sseKmsKeyId?: string;
  customMetadata?: Record<string, string>;
}

export interface S3UploadOptions {
  bucket: string;
  key: string;
  body: Buffer | Uint8Array | string | NodeJS.ReadableStream;
  metadata?: S3ObjectMetadata;
  tagging?: string;
  acl?: S3ACL;
  serverSideEncryption?: string;
  sseCustomerKey?: string;
  sseKmsKeyId?: string;
  storageClass?: StorageClass;
  contentType?: string;
  partSize?: number; // For multipart uploads
  queueSize?: number; // Concurrent parts for multipart
  leavePartsOnError?: boolean;
}

export enum S3ACL {
  PRIVATE = 'private',
  PUBLIC_READ = 'public-read',
  PUBLIC_READ_WRITE = 'public-read-write',
  AUTHENTICATED_READ = 'authenticated-read',
  AWS_EXEC_READ = 'aws-exec-read',
  BUCKET_OWNER_READ = 'bucket-owner-read',
  BUCKET_OWNER_FULL_CONTROL = 'bucket-owner-full-control'
}

export interface S3DownloadOptions {
  bucket: string;
  key: string;
  versionId?: string;
  range?: string; // e.g., 'bytes=0-1023'
  ifMatch?: string;
  ifNoneMatch?: string;
  ifModifiedSince?: Date;
  ifUnmodifiedSince?: Date;
  responseContentType?: string;
  responseContentLanguage?: string;
  responseContentDisposition?: string;
  responseContentEncoding?: string;
  responseCacheControl?: string;
  responseExpires?: Date;
}

export interface S3ListOptions {
  bucket: string;
  prefix?: string;
  delimiter?: string;
  maxKeys?: number;
  continuationToken?: string;
  startAfter?: string;
  fetchOwner?: boolean;
}

export interface S3ListResult {
  contents: S3Object[];
  commonPrefixes?: string[];
  isTruncated: boolean;
  nextContinuationToken?: string;
  keyCount: number;
}

export interface S3CopyOptions {
  sourceBucket: string;
  sourceKey: string;
  destinationBucket: string;
  destinationKey: string;
  sourceVersionId?: string;
  metadata?: S3ObjectMetadata;
  metadataDirective?: 'COPY' | 'REPLACE';
  tagging?: string;
  taggingDirective?: 'COPY' | 'REPLACE';
  acl?: S3ACL;
  storageClass?: StorageClass;
  serverSideEncryption?: string;
  sseKmsKeyId?: string;
}

export interface S3DeleteOptions {
  bucket: string;
  delete: {
    objects: Array<{
      key: string;
      versionId?: string;
    }>;
    quiet?: boolean;
  };
}

export interface S3DeleteResult {
  deleted: Array<{
    key: string;
    versionId?: string;
  }>;
  errors: Array<{
    key: string;
    versionId?: string;
    code: string;
    message: string;
  }>;
}

// S3 Multipart Upload

export interface S3MultipartUpload {
  uploadId: string;
  bucket: string;
  key: string;
  initiated: Date;
  storageClass?: StorageClass;
  owner?: S3Owner;
}

export interface S3Part {
  partNumber: number;
  etag: string;
  size?: number;
  lastModified?: Date;
}

export interface S3MultipartUploadOptions extends S3UploadOptions {
  partSize?: number; // Size of each part (min 5MB)
  queueSize?: number; // Number of concurrent uploads
  leavePartsOnError?: boolean;
}

// S3 Presigned URLs

export interface S3PresignedUrlOptions {
  bucket: string;
  key: string;
  expires: number; // seconds
  operation: 'getObject' | 'putObject';
  contentType?: string;
  acl?: S3ACL;
  metadata?: Record<string, string>;
  versionId?: string;
}

export interface S3PresignedPostOptions {
  bucket: string;
  expires: number; // seconds
  conditions?: S3PostCondition[];
  fields?: Record<string, string>;
}

export type S3PostCondition = 
  | ['eq', string, string]
  | ['starts-with', string, string]
  | ['content-length-range', number, number]
  | Record<string, string>;

// S3 Event Notifications

export interface S3Event {
  records: S3EventRecord[];
}

export interface S3EventRecord {
  eventVersion: string;
  eventSource: string;
  awsRegion: string;
  eventTime: string;
  eventName: S3EventName;
  userIdentity?: S3UserIdentity;
  requestParameters?: Record<string, any>;
  responseElements?: Record<string, any>;
  s3: S3EventData;
}

export enum S3EventName {
  OBJECT_CREATED_PUT = 's3:ObjectCreated:Put',
  OBJECT_CREATED_POST = 's3:ObjectCreated:Post',
  OBJECT_CREATED_COPY = 's3:ObjectCreated:Copy',
  OBJECT_CREATED_MULTIPART = 's3:ObjectCreated:CompleteMultipartUpload',
  OBJECT_REMOVED_DELETE = 's3:ObjectRemoved:Delete',
  OBJECT_REMOVED_DELETE_MARKER = 's3:ObjectRemoved:DeleteMarkerCreated',
  OBJECT_RESTORE_COMPLETED = 's3:ObjectRestore:Completed',
  REPLICATION_FAILED = 's3:Replication:OperationFailedReplication'
}

export interface S3UserIdentity {
  principalId: string;
}

export interface S3EventData {
  s3SchemaVersion: string;
  configurationId: string;
  bucket: S3EventBucket;
  object: S3EventObject;
}

export interface S3EventBucket {
  name: string;
  ownerIdentity: S3Owner;
  arn: string;
}

export interface S3EventObject {
  key: string;
  size: number;
  etag: string;
  versionId?: string;
  sequencer: string;
}

// S3 Manager Interfaces

export interface S3Manager {
  upload(options: S3UploadOptions): Promise<S3UploadResult>;
  download(options: S3DownloadOptions): Promise<S3DownloadResult>;
  copy(options: S3CopyOptions): Promise<S3CopyResult>;
  delete(options: S3DeleteOptions): Promise<S3DeleteResult>;
  list(options: S3ListOptions): Promise<S3ListResult>;
  headObject(bucket: string, key: string): Promise<S3Object>;
  getPresignedUrl(options: S3PresignedUrlOptions): Promise<string>;
  createMultipartUpload(options: S3UploadOptions): Promise<S3MultipartUpload>;
  uploadPart(uploadId: string, partNumber: number, body: Buffer): Promise<S3Part>;
  completeMultipartUpload(uploadId: string, parts: S3Part[]): Promise<S3UploadResult>;
  abortMultipartUpload(uploadId: string): Promise<void>;
}

export interface S3UploadResult {
  location: string;
  bucket: string;
  key: string;
  etag: string;
  versionId?: string;
}

export interface S3DownloadResult {
  body: Buffer | NodeJS.ReadableStream;
  metadata: S3ObjectMetadata;
  contentLength: number;
  contentType?: string;
  etag: string;
  versionId?: string;
}

export interface S3CopyResult {
  copyObjectResult: {
    etag: string;
    lastModified: Date;
  };
  versionId?: string;
}

// S3 Metrics

export interface S3Metrics {
  uploads: S3OperationMetrics;
  downloads: S3OperationMetrics;
  deletes: S3OperationMetrics;
  copies: S3OperationMetrics;
  lists: S3OperationMetrics;
  totalBandwidth: S3BandwidthMetrics;
}

export interface S3OperationMetrics {
  count: number;
  successCount: number;
  errorCount: number;
  totalBytes: number;
  totalDuration: number;
  averageDuration: number;
  errors: S3ErrorMetric[];
}

export interface S3ErrorMetric {
  code: string;
  message: string;
  count: number;
  lastOccurrence: Date;
}

export interface S3BandwidthMetrics {
  uploadBytes: number;
  downloadBytes: number;
  uploadRate: number; // bytes/second
  downloadRate: number; // bytes/second
}