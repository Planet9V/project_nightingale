import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { logger } from '../utils/logger';
import * as cliProgress from 'cli-progress';
import chalk from 'chalk';

export interface ProcessingProgress {
  batchId: string;
  totalFiles: number;
  processedFiles: number;
  successfulFiles: number;
  failedFiles: number;
  totalChunks: number;
  processedChunks: number;
  totalEmbeddings: number;
  processedEmbeddings: number;
  startTime: Date;
  estimatedCompletion?: Date;
  currentFile?: string;
  currentStage?: string;
  averageProcessingTime?: number;
  errors: Array<{
    file: string;
    error: string;
    timestamp: Date;
  }>;
}

export interface FileProgress {
  fileId: string;
  fileName: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  chunks: number;
  processedChunks: number;
  embeddings: number;
  processedEmbeddings: number;
  startTime?: Date;
  endTime?: Date;
  error?: string;
}

export class ProgressTracker {
  private supabase: SupabaseClient;
  private progress: ProcessingProgress;
  private fileProgress: Map<string, FileProgress> = new Map();
  private multibar: cliProgress.MultiBar;
  private bars: Map<string, cliProgress.SingleBar> = new Map();
  private updateInterval: NodeJS.Timer;
  private persistInterval: NodeJS.Timer;

  constructor(
    supabaseUrl: string,
    supabaseKey: string,
    batchId: string
  ) {
    this.supabase = createClient(supabaseUrl, supabaseKey);
    
    this.progress = {
      batchId,
      totalFiles: 0,
      processedFiles: 0,
      successfulFiles: 0,
      failedFiles: 0,
      totalChunks: 0,
      processedChunks: 0,
      totalEmbeddings: 0,
      processedEmbeddings: 0,
      startTime: new Date(),
      errors: [],
    };

    // Initialize CLI progress bars
    this.multibar = new cliProgress.MultiBar({
      clearOnComplete: false,
      hideCursor: true,
      format: '{bar} | {task} | {value}/{total} | {percentage}% | ETA: {eta_formatted}',
    }, cliProgress.Presets.shades_classic);

    // Start update intervals
    this.startUpdateLoop();
    this.startPersistenceLoop();
  }

  private startUpdateLoop(): void {
    this.updateInterval = setInterval(() => {
      this.updateEstimates();
      this.displayStats();
    }, 1000);
  }

  private startPersistenceLoop(): void {
    this.persistInterval = setInterval(async () => {
      await this.persistProgress();
    }, 5000); // Persist every 5 seconds
  }

  async initialize(totalFiles: number): Promise<void> {
    this.progress.totalFiles = totalFiles;
    
    // Create main progress bars
    this.bars.set('files', this.multibar.create(totalFiles, 0, { task: 'Files' }));
    this.bars.set('chunks', this.multibar.create(100, 0, { task: 'Chunks' }));
    this.bars.set('embeddings', this.multibar.create(100, 0, { task: 'Embeddings' }));
    
    // Check for existing progress
    await this.loadExistingProgress();
  }

  async loadExistingProgress(): Promise<void> {
    try {
      const { data, error } = await this.supabase
        .from('etl_checkpoints')
        .select('checkpoint_data')
        .eq('batch_id', this.progress.batchId)
        .eq('checkpoint_type', 'batch')
        .order('created_at', { ascending: false })
        .limit(1)
        .single();

      if (data && !error) {
        const savedProgress = data.checkpoint_data as ProcessingProgress;
        
        // Restore progress
        this.progress = {
          ...this.progress,
          ...savedProgress,
          startTime: new Date(savedProgress.startTime),
        };

        logger.info('Restored previous progress', {
          processedFiles: this.progress.processedFiles,
          totalFiles: this.progress.totalFiles,
        });

        // Update progress bars
        this.updateProgressBars();
      }
    } catch (error) {
      logger.warn('No previous progress found, starting fresh');
    }
  }

  async persistProgress(): Promise<void> {
    try {
      await this.supabase
        .from('etl_checkpoints')
        .upsert({
          batch_id: this.progress.batchId,
          checkpoint_type: 'batch',
          checkpoint_data: this.progress,
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        }, {
          onConflict: 'batch_id,checkpoint_type',
        });
    } catch (error) {
      logger.error('Failed to persist progress', error);
    }
  }

  startFile(fileId: string, fileName: string): void {
    const fileProgress: FileProgress = {
      fileId,
      fileName,
      status: 'processing',
      chunks: 0,
      processedChunks: 0,
      embeddings: 0,
      processedEmbeddings: 0,
      startTime: new Date(),
    };

    this.fileProgress.set(fileId, fileProgress);
    this.progress.currentFile = fileName;
    
    logger.info(`Processing file: ${fileName}`);
  }

  updateFileChunks(fileId: string, totalChunks: number): void {
    const file = this.fileProgress.get(fileId);
    if (file) {
      file.chunks = totalChunks;
      this.progress.totalChunks += totalChunks;
      this.updateProgressBars();
    }
  }

  updateFileProgress(
    fileId: string,
    processedChunks: number,
    processedEmbeddings: number
  ): void {
    const file = this.fileProgress.get(fileId);
    if (file) {
      const chunkDelta = processedChunks - file.processedChunks;
      const embeddingDelta = processedEmbeddings - file.processedEmbeddings;
      
      file.processedChunks = processedChunks;
      file.processedEmbeddings = processedEmbeddings;
      
      this.progress.processedChunks += chunkDelta;
      this.progress.processedEmbeddings += embeddingDelta;
      
      this.updateProgressBars();
    }
  }

  completeFile(fileId: string, success: boolean, error?: string): void {
    const file = this.fileProgress.get(fileId);
    if (file) {
      file.status = success ? 'completed' : 'failed';
      file.endTime = new Date();
      
      if (error) {
        file.error = error;
        this.progress.errors.push({
          file: file.fileName,
          error,
          timestamp: new Date(),
        });
      }
      
      this.progress.processedFiles++;
      if (success) {
        this.progress.successfulFiles++;
      } else {
        this.progress.failedFiles++;
      }
      
      this.updateProgressBars();
    }
  }

  updateStage(stage: string): void {
    this.progress.currentStage = stage;
  }

  private updateEstimates(): void {
    if (this.progress.processedFiles > 0) {
      const elapsedMs = Date.now() - this.progress.startTime.getTime();
      const avgTimePerFile = elapsedMs / this.progress.processedFiles;
      const remainingFiles = this.progress.totalFiles - this.progress.processedFiles;
      const estimatedRemainingMs = remainingFiles * avgTimePerFile;
      
      this.progress.averageProcessingTime = avgTimePerFile;
      this.progress.estimatedCompletion = new Date(Date.now() + estimatedRemainingMs);
    }
  }

  private updateProgressBars(): void {
    // Update file progress
    const filesBar = this.bars.get('files');
    if (filesBar) {
      filesBar.update(this.progress.processedFiles);
    }

    // Update chunks progress
    const chunksBar = this.bars.get('chunks');
    if (chunksBar && this.progress.totalChunks > 0) {
      chunksBar.setTotal(this.progress.totalChunks);
      chunksBar.update(this.progress.processedChunks);
    }

    // Update embeddings progress
    const embeddingsBar = this.bars.get('embeddings');
    if (embeddingsBar && this.progress.totalEmbeddings > 0) {
      embeddingsBar.setTotal(this.progress.totalEmbeddings);
      embeddingsBar.update(this.progress.processedEmbeddings);
    }
  }

  private displayStats(): void {
    const stats = this.getStats();
    
    // Clear previous line and display stats
    process.stdout.write('\r\x1b[K'); // Clear line
    process.stdout.write(
      chalk.cyan(`Speed: ${stats.filesPerMinute.toFixed(1)} files/min | `) +
      chalk.green(`Success: ${stats.successRate.toFixed(1)}% | `) +
      chalk.yellow(`ETA: ${stats.eta || 'calculating...'} | `) +
      chalk.magenta(`Stage: ${this.progress.currentStage || 'initializing'}`)
    );
  }

  getStats(): {
    filesPerMinute: number;
    chunksPerSecond: number;
    successRate: number;
    eta: string | null;
    elapsedTime: string;
  } {
    const elapsedMs = Date.now() - this.progress.startTime.getTime();
    const elapsedMinutes = elapsedMs / 60000;
    const elapsedSeconds = elapsedMs / 1000;
    
    const filesPerMinute = this.progress.processedFiles / elapsedMinutes;
    const chunksPerSecond = this.progress.processedChunks / elapsedSeconds;
    const successRate = this.progress.processedFiles > 0
      ? (this.progress.successfulFiles / this.progress.processedFiles) * 100
      : 0;
    
    let eta: string | null = null;
    if (this.progress.estimatedCompletion) {
      const remaining = this.progress.estimatedCompletion.getTime() - Date.now();
      const hours = Math.floor(remaining / 3600000);
      const minutes = Math.floor((remaining % 3600000) / 60000);
      const seconds = Math.floor((remaining % 60000) / 1000);
      eta = `${hours}h ${minutes}m ${seconds}s`;
    }
    
    const elapsedHours = Math.floor(elapsedMinutes / 60);
    const elapsedMins = Math.floor(elapsedMinutes % 60);
    const elapsedSecs = Math.floor(elapsedSeconds % 60);
    const elapsedTime = `${elapsedHours}h ${elapsedMins}m ${elapsedSecs}s`;
    
    return {
      filesPerMinute,
      chunksPerSecond,
      successRate,
      eta,
      elapsedTime,
    };
  }

  async getFailedFiles(): Promise<string[]> {
    return Array.from(this.fileProgress.values())
      .filter(f => f.status === 'failed')
      .map(f => f.fileName);
  }

  async generateReport(): Promise<string> {
    const stats = this.getStats();
    
    const report = `
ETL Pipeline Processing Report
==============================
Batch ID: ${this.progress.batchId}
Started: ${this.progress.startTime.toISOString()}
Completed: ${new Date().toISOString()}

Summary:
--------
Total Files: ${this.progress.totalFiles}
Processed: ${this.progress.processedFiles}
Successful: ${this.progress.successfulFiles}
Failed: ${this.progress.failedFiles}

Performance:
------------
Processing Speed: ${stats.filesPerMinute.toFixed(2)} files/minute
Chunk Processing: ${stats.chunksPerSecond.toFixed(2)} chunks/second
Success Rate: ${stats.successRate.toFixed(2)}%
Total Time: ${stats.elapsedTime}

Chunks & Embeddings:
--------------------
Total Chunks: ${this.progress.totalChunks}
Processed Chunks: ${this.progress.processedChunks}
Total Embeddings: ${this.progress.totalEmbeddings}
Processed Embeddings: ${this.progress.processedEmbeddings}

${this.progress.errors.length > 0 ? `
Errors:
-------
${this.progress.errors.map(e => `- ${e.file}: ${e.error} (${e.timestamp.toISOString()})`).join('\n')}
` : ''}
`;

    return report;
  }

  async cleanup(): Promise<void> {
    clearInterval(this.updateInterval);
    clearInterval(this.persistInterval);
    
    // Final persist
    await this.persistProgress();
    
    // Stop progress bars
    this.multibar.stop();
    
    // Display final report
    console.log('\n\n' + await this.generateReport());
  }
}