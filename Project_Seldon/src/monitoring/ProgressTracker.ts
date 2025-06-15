import { EventEmitter } from 'events';

export interface ProgressEvent {
  stage: string;
  progress: number;
  message?: string;
  metadata?: any;
}

export class ProgressTracker extends EventEmitter {
  private progress: Map<string, number> = new Map();
  private fileStatus: Map<string, 'pending' | 'processing' | 'completed' | 'failed'> = new Map();
  private fileChunks: Map<string, number> = new Map();
  private failedFiles: string[] = [];
  private startTime: number = Date.now();
  private resumeState: any = null;

  updateProgress(stage: string, progress: number, message?: string): void {
    this.progress.set(stage, progress);
    const event: ProgressEvent = { stage, progress, message };
    this.emit('progress', event);
    
    if (progress === 100) {
      this.emit('milestone', { stage, message: `${stage} completed` });
    }
  }

  getProgress(stage: string): number {
    return this.progress.get(stage) || 0;
  }

  getAllProgress(): Map<string, number> {
    return new Map(this.progress);
  }

  reset(): void {
    this.progress.clear();
    this.fileStatus.clear();
    this.fileChunks.clear();
    this.failedFiles = [];
  }

  // File tracking methods
  startFile(filePath: string): void {
    this.fileStatus.set(filePath, 'processing');
    this.emit('file-started', { filePath });
  }

  completeFile(filePath: string, status: 'completed' | 'failed' = 'completed', error?: any): void {
    this.fileStatus.set(filePath, status);
    if (status === 'failed') {
      this.failedFiles.push(filePath);
    }
    this.emit('file-completed', { filePath, status, error });
  }

  updateFileChunks(filePath: string, chunks: number): void {
    this.fileChunks.set(filePath, chunks);
  }

  getFailedFiles(): string[] {
    return [...this.failedFiles];
  }

  // Initialization and cleanup
  initialize(resumeState?: any): void {
    if (resumeState) {
      this.resumeState = resumeState;
      // Restore state if needed
    }
    this.startTime = Date.now();
  }

  cleanup(): void {
    this.removeAllListeners();
    this.reset();
  }

  // Reporting
  generateReport(): any {
    const completedFiles = Array.from(this.fileStatus.entries())
      .filter(([_, status]) => status === 'completed')
      .map(([file, _]) => file);
    
    const processingTime = Date.now() - this.startTime;
    
    return {
      totalFiles: this.fileStatus.size,
      completedFiles: completedFiles.length,
      failedFiles: this.failedFiles.length,
      fileDetails: Object.fromEntries(this.fileStatus),
      chunks: Object.fromEntries(this.fileChunks),
      processingTime,
      progress: Object.fromEntries(this.progress)
    };
  }
}