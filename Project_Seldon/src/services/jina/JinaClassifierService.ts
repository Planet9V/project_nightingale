/**
 * JinaClassifierService - Advanced Content Classification and Labeling
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import {
  JinaClassifierRequest,
  JinaClassifierResponse,
  JinaAPIError,
  ContentClassification,
  DocumentChunk,
  DEFAULT_CLASSIFICATION_LABELS,
  ClassificationLabel,
  JINA_SERVICE_CONFIGS
} from '../../types/jina';
import { JinaRateLimiter } from './JinaRateLimiter';

export interface ClassificationResult {
  primary_label: string;
  confidence: number;
  all_scores: Array<{
    label: string;
    score: number;
  }>;
  is_multi_label?: boolean;
  threshold_passed?: boolean;
}

export interface BatchClassificationResult {
  text: string;
  classification: ClassificationResult;
  processing_time_ms: number;
}

export interface ChunkClassificationResult {
  chunk_id: string;
  chunk: DocumentChunk;
  classification: ClassificationResult;
  processing_time_ms: number;
}

export class JinaClassifierService {
  private rateLimiter: JinaRateLimiter;
  private apiKey: string;
  private config = JINA_SERVICE_CONFIGS.classifier;
  private logger: Console;

  constructor(
    rateLimiter: JinaRateLimiter,
    apiKey: string,
    logger: Console = console
  ) {
    this.rateLimiter = rateLimiter;
    this.apiKey = apiKey;
    this.logger = logger;
  }

  /**
   * Classify a single text with custom or default labels
   */
  async classifyText(
    text: string,
    options: {
      model?: string;
      labels?: string[];
      multi_label?: boolean;
      confidence_threshold?: number;
      max_length?: number;
    } = {}
  ): Promise<ClassificationResult> {
    const labels = options.labels || [...DEFAULT_CLASSIFICATION_LABELS];
    const maxLength = options.max_length || 2000;
    const truncatedText = text.length > maxLength ? text.substring(0, maxLength) : text;

    const request: JinaClassifierRequest = {
      model: options.model || this.config.model,
      input: truncatedText,
      labels,
      multi_label: options.multi_label || false
    };

    const response = await this.rateLimiter.processWithLimit(
      'classifier',
      () => this.makeClassificationRequest(request),
      {
        metadata: {
          originalTextLength: text.length,
          truncatedTextLength: truncatedText.length,
          labelCount: labels.length,
          multiLabel: options.multi_label || false
        }
      }
    );

    const result: ClassificationResult = {
      primary_label: response.prediction,
      confidence: this.findLabelScore(response.scores, response.prediction),
      all_scores: response.scores.sort((a, b) => b.score - a.score),
      is_multi_label: options.multi_label,
      threshold_passed: options.confidence_threshold ? 
        this.findLabelScore(response.scores, response.prediction) >= options.confidence_threshold : 
        undefined
    };

    return result;
  }

  /**
   * Classify multiple texts in batch
   */
  async classifyBatch(
    texts: string[],
    options: {
      model?: string;
      labels?: string[];
      multi_label?: boolean;
      confidence_threshold?: number;
      max_length?: number;
      batchSize?: number;
    } = {}
  ): Promise<BatchClassificationResult[]> {
    if (texts.length === 0) {
      return [];
    }

    const batchSize = options.batchSize || 5; // Conservative batch size due to 60 RPM limit
    const results: BatchClassificationResult[] = [];

    this.logger.log(`Classifying ${texts.length} texts in batches of ${batchSize}`);

    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (text, index) => {
        const startTime = Date.now();
        
        try {
          const classification = await this.classifyText(text, options);
          const processingTime = Date.now() - startTime;
          
          return {
            text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
            classification,
            processing_time_ms: processingTime
          };
        } catch (error) {
          this.logger.error(`Classification failed for text ${i + index}:`, error);
          throw error;
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      this.logger.log(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(texts.length / batchSize)}`);

      // Add delay between batches to respect rate limits
      if (i + batchSize < texts.length) {
        await this.sleep(2000); // 2 second delay
      }
    }

    return results;
  }

  /**
   * Classify document chunks with full metadata preservation
   */
  async classifyChunks(
    chunks: DocumentChunk[],
    options: {
      model?: string;
      labels?: string[];
      multi_label?: boolean;
      confidence_threshold?: number;
      max_length?: number;
      batchSize?: number;
    } = {}
  ): Promise<ChunkClassificationResult[]> {
    if (chunks.length === 0) {
      return [];
    }

    this.logger.log(`Classifying ${chunks.length} document chunks`);

    const batchSize = options.batchSize || 3; // Even more conservative for chunks
    const results: ChunkClassificationResult[] = [];

    for (let i = 0; i < chunks.length; i += batchSize) {
      const batch = chunks.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (chunk, index) => {
        const startTime = Date.now();
        
        try {
          const classification = await this.classifyText(chunk.content, options);
          const processingTime = Date.now() - startTime;
          
          return {
            chunk_id: chunk.chunk_id,
            chunk,
            classification,
            processing_time_ms: processingTime
          };
        } catch (error) {
          this.logger.error(`Classification failed for chunk ${chunk.chunk_id}:`, error);
          throw error;
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      this.logger.log(`Processed chunk batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(chunks.length / batchSize)}`);

      // Add delay between batches
      if (i + batchSize < chunks.length) {
        await this.sleep(3000); // 3 second delay for chunks
      }
    }

    return results;
  }

  /**
   * Classify with cybersecurity-specific labels
   */
  async classifyCybersecurity(
    text: string,
    options: {
      model?: string;
      confidence_threshold?: number;
      include_general_labels?: boolean;
    } = {}
  ): Promise<ClassificationResult> {
    const cybersecurityLabels = [
      'threat_intelligence',
      'vulnerability_assessment',
      'incident_response',
      'malware_analysis',
      'network_security',
      'endpoint_security',
      'application_security',
      'cloud_security',
      'compliance_audit',
      'risk_assessment',
      'penetration_testing',
      'security_advisory',
      'threat_hunting',
      'forensic_analysis'
    ];

    const labels = options.include_general_labels ? 
      [...cybersecurityLabels, ...DEFAULT_CLASSIFICATION_LABELS] : 
      cybersecurityLabels;

    return this.classifyText(text, {
      model: options.model,
      labels,
      confidence_threshold: options.confidence_threshold
    });
  }

  /**
   * Classify with industry-specific labels
   */
  async classifyIndustry(
    text: string,
    options: {
      model?: string;
      confidence_threshold?: number;
    } = {}
  ): Promise<ClassificationResult> {
    const industryLabels = [
      'energy_utilities',
      'manufacturing',
      'transportation',
      'healthcare',
      'financial_services',
      'telecommunications',
      'government',
      'education',
      'retail',
      'agriculture',
      'defense',
      'critical_infrastructure'
    ];

    return this.classifyText(text, {
      model: options.model,
      labels: industryLabels,
      confidence_threshold: options.confidence_threshold
    });
  }

  /**
   * Multi-label classification for complex documents
   */
  async classifyMultiLabel(
    text: string,
    options: {
      model?: string;
      labels?: string[];
      confidence_threshold?: number;
      max_labels?: number;
    } = {}
  ): Promise<{
    labels: string[];
    scores: Array<{ label: string; score: number; }>;
    above_threshold: Array<{ label: string; score: number; }>;
  }> {
    const threshold = options.confidence_threshold || 0.5;
    const maxLabels = options.max_labels || 5;

    const result = await this.classifyText(text, {
      model: options.model,
      labels: options.labels,
      multi_label: true,
      confidence_threshold: threshold
    });

    const aboveThreshold = result.all_scores
      .filter(score => score.score >= threshold)
      .slice(0, maxLabels);

    return {
      labels: aboveThreshold.map(s => s.label),
      scores: result.all_scores,
      above_threshold: aboveThreshold
    };
  }

  /**
   * Get classification confidence statistics
   */
  analyzeClassificationConfidence(
    results: ClassificationResult[]
  ): {
    mean_confidence: number;
    median_confidence: number;
    std_confidence: number;
    min_confidence: number;
    max_confidence: number;
    low_confidence_count: number;
    high_confidence_count: number;
  } {
    if (results.length === 0) {
      return {
        mean_confidence: 0,
        median_confidence: 0,
        std_confidence: 0,
        min_confidence: 0,
        max_confidence: 0,
        low_confidence_count: 0,
        high_confidence_count: 0
      };
    }

    const confidences = results.map(r => r.confidence).sort((a, b) => a - b);
    const mean = confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length;
    const median = confidences[Math.floor(confidences.length / 2)];
    const variance = confidences.reduce((sum, conf) => sum + Math.pow(conf - mean, 2), 0) / confidences.length;
    const std = Math.sqrt(variance);
    const min = confidences[0];
    const max = confidences[confidences.length - 1];
    const lowConfidenceCount = confidences.filter(c => c < 0.7).length;
    const highConfidenceCount = confidences.filter(c => c >= 0.9).length;

    return {
      mean_confidence: mean,
      median_confidence: median,
      std_confidence: std,
      min_confidence: min,
      max_confidence: max,
      low_confidence_count: lowConfidenceCount,
      high_confidence_count: highConfidenceCount
    };
  }

  /**
   * Get label distribution from classification results
   */
  getLabelDistribution(
    results: ClassificationResult[]
  ): Array<{
    label: string;
    count: number;
    percentage: number;
    avg_confidence: number;
  }> {
    const labelCounts = new Map<string, { count: number; total_confidence: number }>();

    results.forEach(result => {
      const current = labelCounts.get(result.primary_label) || { count: 0, total_confidence: 0 };
      labelCounts.set(result.primary_label, {
        count: current.count + 1,
        total_confidence: current.total_confidence + result.confidence
      });
    });

    return Array.from(labelCounts.entries())
      .map(([label, stats]) => ({
        label,
        count: stats.count,
        percentage: (stats.count / results.length) * 100,
        avg_confidence: stats.total_confidence / stats.count
      }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Filter results by confidence threshold
   */
  filterByConfidence(
    results: ClassificationResult[],
    threshold: number
  ): {
    passed: ClassificationResult[];
    failed: ClassificationResult[];
    statistics: {
      total: number;
      passed: number;
      failed: number;
      pass_rate: number;
    };
  } {
    const passed = results.filter(r => r.confidence >= threshold);
    const failed = results.filter(r => r.confidence < threshold);

    return {
      passed,
      failed,
      statistics: {
        total: results.length,
        passed: passed.length,
        failed: failed.length,
        pass_rate: results.length > 0 ? passed.length / results.length : 0
      }
    };
  }

  /**
   * Helper method to find score for a specific label
   */
  private findLabelScore(scores: Array<{ label: string; score: number }>, label: string): number {
    const found = scores.find(s => s.label === label);
    return found ? found.score : 0;
  }

  /**
   * Sleep utility for rate limiting
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Make HTTP request to Jina Classification API
   */
  private async makeClassificationRequest(request: JinaClassifierRequest): Promise<JinaClassifierResponse> {
    const startTime = Date.now();

    try {
      const response = await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'User-Agent': 'Project-Seldon/1.0'
        },
        body: JSON.stringify(request)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new JinaAPIError(data);
      }

      const processingTime = Date.now() - startTime;
      this.logger.log(`Classification request completed in ${processingTime}ms`);

      // Validate response structure
      if (!data.prediction || !data.scores || !Array.isArray(data.scores)) {
        throw new Error('Invalid classification response structure');
      }

      return data;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error(`Classification request failed after ${processingTime}ms:`, error);
      throw error;
    }
  }

  /**
   * Get service configuration
   */
  getConfig() {
    return {
      ...this.config,
      apiKeyConfigured: !!this.apiKey,
      defaultLabels: DEFAULT_CLASSIFICATION_LABELS
    };
  }

  /**
   * Test service connectivity
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.classifyText('This is a test document about cybersecurity threats.', {
        labels: ['cybersecurity', 'general', 'test'],
        confidence_threshold: 0.1
      });
      this.logger.log('Jina Classification Service connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Jina Classification Service connection test failed:', error);
      return false;
    }
  }
}