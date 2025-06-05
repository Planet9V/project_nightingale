import { logger } from '../utils/logger';

export interface JinaAIConfig {
  apiKey: string;
  baseURL?: string;
}

export interface JinaEmbeddingRequest {
  model: string;
  input: string | string[];
  encoding_format?: 'float' | 'base64';
  task?: 'retrieval.query' | 'retrieval.passage' | 'separation' | 'classification' | 'text-matching';
  dimensions?: number;
  late_chunking?: boolean;
  input_type?: 'query' | 'document';
}

export interface JinaEmbeddingResponse {
  object: string;
  data: Array<{
    object: string;
    index: number;
    embedding: number[];
  }>;
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

export interface JinaRerankRequest {
  model: string;
  query: string;
  documents: string[];
  top_n?: number;
  return_documents?: boolean;
}

export interface JinaRerankResponse {
  model: string;
  usage: {
    total_tokens: number;
    prompt_tokens: number;
  };
  results: Array<{
    index: number;
    document?: {
      text: string;
    };
    relevance_score: number;
  }>;
}

export interface JinaClassificationRequest {
  model: string;
  input: string;
  labels: string[];
}

export interface JinaClassificationResponse {
  predictions: Array<{
    id: number;
    label: string;
    score: number;
  }>;
  usage: {
    total_tokens: number;
  };
}

export class JinaAIService {
  private apiKey: string;
  private baseURL: string = 'https://api.jina.ai/v1';

  constructor(config?: JinaAIConfig) {
    this.apiKey = config?.apiKey || process.env.JINA_API_KEY || '';
    this.baseURL = config?.baseURL || this.baseURL;
    
    if (!this.apiKey) {
      logger.warn('Jina AI API key not provided');
    }
  }

  // Available Jina models
  public models = {
    // Embedding models
    EMBEDDINGS_V2_BASE_EN: 'jina-embeddings-v2-base-en',
    EMBEDDINGS_V2_SMALL_EN: 'jina-embeddings-v2-small-en',
    EMBEDDINGS_V3: 'jina-embeddings-v3',
    CLIP_V1: 'jina-clip-v1',
    COLBERT_V2: 'jina-colbert-v2',
    
    // Reranking models
    RERANKER_V2_BASE_MULTILINGUAL: 'jina-reranker-v2-base-multilingual',
    RERANKER_V1_TURBO_EN: 'jina-reranker-v1-turbo-en',
    RERANKER_V1_TINY_EN: 'jina-reranker-v1-tiny-en',
    
    // Classification models
    CLASSIFIER_V1: 'jina-classifier-v1',
  };

  async generateEmbedding(request: JinaEmbeddingRequest): Promise<JinaEmbeddingResponse> {
    if (!this.apiKey) {
      throw new Error('Jina AI API key is required');
    }

    const url = `${this.baseURL}/embeddings`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Jina AI API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      logger.error('Jina AI embedding request failed:', error);
      throw new Error(`Jina AI embedding request failed: ${error.message}`);
    }
  }

  async rerank(request: JinaRerankRequest): Promise<JinaRerankResponse> {
    if (!this.apiKey) {
      throw new Error('Jina AI API key is required');
    }

    const url = `${this.baseURL}/rerank`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Jina AI API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      logger.error('Jina AI rerank request failed:', error);
      throw new Error(`Jina AI rerank request failed: ${error.message}`);
    }
  }

  async classify(request: JinaClassificationRequest): Promise<JinaClassificationResponse> {
    if (!this.apiKey) {
      throw new Error('Jina AI API key is required');
    }

    const url = `${this.baseURL}/classify`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Jina AI API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      logger.error('Jina AI classification request failed:', error);
      throw new Error(`Jina AI classification request failed: ${error.message}`);
    }
  }

  // Vehicle-specific methods
  async generateVehicleEmbedding(
    text: string,
    type: 'query' | 'document' = 'document'
  ): Promise<number[]> {
    const response = await this.generateEmbedding({
      model: this.models.EMBEDDINGS_V3,
      input: text,
      task: type === 'query' ? 'retrieval.query' : 'retrieval.passage',
      input_type: type,
      dimensions: 1024, // Jina v3 supports up to 1024 dimensions
    });

    return response.data[0].embedding;
  }

  async generateMultipleEmbeddings(
    texts: string[],
    type: 'query' | 'document' = 'document'
  ): Promise<number[][]> {
    const response = await this.generateEmbedding({
      model: this.models.EMBEDDINGS_V3,
      input: texts,
      task: type === 'query' ? 'retrieval.query' : 'retrieval.passage',
      input_type: type,
      dimensions: 1024,
    });

    return response.data.map(item => item.embedding);
  }

  async rerankVehicleResults(
    query: string,
    documents: string[],
    topN: number = 10
  ): Promise<JinaRerankResponse> {
    return this.rerank({
      model: this.models.RERANKER_V2_BASE_MULTILINGUAL,
      query,
      documents,
      top_n: topN,
      return_documents: true,
    });
  }

  async classifyVehicleDescription(
    description: string
  ): Promise<JinaClassificationResponse> {
    const vehicleLabels = [
      'muscle car',
      'sports car',
      'luxury car',
      'classic car',
      'vintage car',
      'exotic car',
      'truck',
      'suv',
      'sedan',
      'coupe',
      'convertible',
      'hatchback',
      'wagon',
      'roadster',
    ];

    return this.classify({
      model: this.models.CLASSIFIER_V1,
      input: description,
      labels: vehicleLabels,
    });
  }

  async classifyVehicleCondition(
    description: string
  ): Promise<JinaClassificationResponse> {
    const conditionLabels = [
      'excellent',
      'very good',
      'good',
      'fair',
      'poor',
      'project car',
      'restoration needed',
      'barn find',
      'numbers matching',
      'original condition',
      'restored',
      'modified',
      'race car',
    ];

    return this.classify({
      model: this.models.CLASSIFIER_V1,
      input: description,
      labels: conditionLabels,
    });
  }

  async classifyVehicleEra(
    description: string
  ): Promise<JinaClassificationResponse> {
    const eraLabels = [
      'pre-war',
      'post-war',
      '1950s',
      '1960s',
      '1970s',
      '1980s',
      '1990s',
      '2000s',
      'modern classic',
      'future classic',
    ];

    return this.classify({
      model: this.models.CLASSIFIER_V1,
      input: description,
      labels: eraLabels,
    });
  }

  async generateSemanticSearch(
    searchQuery: string,
    vehicleDescriptions: string[],
    topResults: number = 10
  ): Promise<{
    queryEmbedding: number[];
    rankedResults: JinaRerankResponse;
  }> {
    // Generate query embedding
    const queryEmbedding = await this.generateVehicleEmbedding(searchQuery, 'query');
    
    // Rerank results based on semantic similarity
    const rankedResults = await this.rerankVehicleResults(
      searchQuery,
      vehicleDescriptions,
      topResults
    );

    return {
      queryEmbedding,
      rankedResults,
    };
  }

  async healthCheck(): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const response = await this.generateEmbedding({
        model: this.models.EMBEDDINGS_V2_SMALL_EN,
        input: 'test',
      });
      return !!response.data && response.data.length > 0;
    } catch (error) {
      logger.error('Jina AI health check failed:', error);
      return false;
    }
  }

  async getModelInfo(): Promise<any> {
    try {
      // Jina doesn't have a models endpoint, so return our known models
      return {
        embedding_models: [
          this.models.EMBEDDINGS_V2_BASE_EN,
          this.models.EMBEDDINGS_V2_SMALL_EN,
          this.models.EMBEDDINGS_V3,
          this.models.CLIP_V1,
          this.models.COLBERT_V2,
        ],
        reranking_models: [
          this.models.RERANKER_V2_BASE_MULTILINGUAL,
          this.models.RERANKER_V1_TURBO_EN,
          this.models.RERANKER_V1_TINY_EN,
        ],
        classification_models: [
          this.models.CLASSIFIER_V1,
        ],
      };
    } catch (error) {
      logger.error('Failed to get Jina AI model info:', error);
      return { models: this.models };
    }
  }
}

// Export singleton instance
export const jinaAIService = new JinaAIService();