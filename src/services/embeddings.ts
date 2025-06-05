import { logger } from '../utils/logger';
import axios from 'axios';

// Embedding dimensions must match Pinecone index dimensions
export const EMBEDDING_DIMENSIONS = {
  TEXT: 768,      // For text embeddings (descriptions, etc.)
  IMAGE: 512,     // For image embeddings
  SMALL: 256,     // For smaller embeddings (modifications)
  COMPACT: 128,   // For compact embeddings (market trends)
} as const;

// Option 1: Use OpenAI Embeddings (Recommended for production)
export const generateOpenAIEmbedding = async (
  text: string,
  model: 'text-embedding-3-small' | 'text-embedding-3-large' = 'text-embedding-3-small'
): Promise<number[]> => {
  try {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    const response = await axios.post(
      'https://api.openai.com/v1/embeddings',
      {
        input: text,
        model: model,
        dimensions: EMBEDDING_DIMENSIONS.TEXT, // OpenAI allows dimension specification
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );

    return response.data.data[0].embedding;
  } catch (error) {
    logger.error('Failed to generate OpenAI embedding:', error);
    throw error;
  }
};

// Option 2: Use Ollama for Local Embeddings (Free, but requires local setup)
export const generateOllamaEmbedding = async (
  text: string,
  model: string = 'nomic-embed-text' // Good embedding model for Ollama
): Promise<number[]> => {
  try {
    const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
    
    const response = await axios.post(
      `${ollamaUrl}/api/embeddings`,
      {
        model: model,
        prompt: text,
      }
    );

    return response.data.embedding;
  } catch (error) {
    logger.error('Failed to generate Ollama embedding:', error);
    throw error;
  }
};

// Option 3: Use Hugging Face Inference API (Free tier available)
export const generateHuggingFaceEmbedding = async (
  text: string,
  model: string = 'sentence-transformers/all-MiniLM-L6-v2'
): Promise<number[]> => {
  try {
    const apiKey = process.env.HUGGINGFACE_API_KEY;
    if (!apiKey) {
      throw new Error('Hugging Face API key not configured');
    }

    const response = await axios.post(
      `https://api-inference.huggingface.co/models/${model}`,
      {
        inputs: text,
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );

    return response.data;
  } catch (error) {
    logger.error('Failed to generate Hugging Face embedding:', error);
    throw error;
  }
};

// Option 4: Use OpenRouter (Multiple models via single API)
export const generateOpenRouterEmbedding = async (
  text: string,
  model: string = 'text-embedding-3-small'
): Promise<number[]> => {
  try {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      throw new Error('OpenRouter API key not configured');
    }

    const response = await axios.post(
      'https://openrouter.ai/api/v1/embeddings',
      {
        input: text,
        model: model,
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': process.env.FRONTEND_URL || 'http://localhost:3000',
          'X-Title': 'Classic Cars AI Backend',
        },
      }
    );

    return response.data.data[0].embedding;
  } catch (error) {
    logger.error('Failed to generate OpenRouter embedding:', error);
    throw error;
  }
};

// Option 5: Use Cohere Embeddings (Good alternative to OpenAI)
export const generateCohereEmbedding = async (
  texts: string[],
  model: 'embed-english-v3.0' | 'embed-multilingual-v3.0' = 'embed-english-v3.0'
): Promise<number[][]> => {
  try {
    const apiKey = process.env.COHERE_API_KEY;
    if (!apiKey) {
      throw new Error('Cohere API key not configured');
    }

    const response = await axios.post(
      'https://api.cohere.ai/v1/embed',
      {
        texts: texts,
        model: model,
        input_type: 'search_document',
        truncate: 'END',
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );

    return response.data.embeddings;
  } catch (error) {
    logger.error('Failed to generate Cohere embedding:', error);
    throw error;
  }
};

// Main embedding function that uses configured provider
export const generateEmbedding = async (
  text: string,
  type: 'description' | 'search' | 'preference' = 'description'
): Promise<number[]> => {
  const provider = process.env.EMBEDDING_PROVIDER || 'openai';
  
  logger.debug(`Generating ${type} embedding using ${provider}`);

  switch (provider) {
    case 'openai':
      return generateOpenAIEmbedding(text);
    
    case 'openrouter':
      return generateOpenRouterEmbedding(text);
    
    case 'ollama':
      return generateOllamaEmbedding(text);
    
    case 'huggingface':
      return generateHuggingFaceEmbedding(text);
    
    case 'cohere':
      const embeddings = await generateCohereEmbedding([text]);
      return embeddings[0];
    
    default:
      throw new Error(`Unknown embedding provider: ${provider}`);
  }
};

// Batch embedding generation for efficiency
export const generateBatchEmbeddings = async (
  texts: string[],
  type: 'description' | 'search' | 'preference' = 'description'
): Promise<number[][]> => {
  const provider = process.env.EMBEDDING_PROVIDER || 'openai';
  
  logger.debug(`Generating batch embeddings for ${texts.length} texts using ${provider}`);

  switch (provider) {
    case 'openai':
      // OpenAI supports batch embeddings
      const promises = texts.map(text => generateOpenAIEmbedding(text));
      return Promise.all(promises);
    
    case 'cohere':
      // Cohere natively supports batch
      return generateCohereEmbedding(texts);
    
    default:
      // Fall back to sequential for other providers
      const embeddings: number[][] = [];
      for (const text of texts) {
        embeddings.push(await generateEmbedding(text, type));
      }
      return embeddings;
  }
};

// Image embedding generation (requires specialized models)
export const generateImageEmbedding = async (
  imageBuffer: Buffer,
  mimeType: string
): Promise<number[]> => {
  // This would require a multimodal model like CLIP
  // For now, returning a placeholder
  logger.warn('Image embedding generation not implemented yet');
  return new Array(EMBEDDING_DIMENSIONS.IMAGE).fill(0);
};

// Utility to ensure embedding dimensions match index requirements
export const validateEmbeddingDimensions = (
  embedding: number[],
  expectedDimension: number
): boolean => {
  if (embedding.length !== expectedDimension) {
    logger.error(`Embedding dimension mismatch: got ${embedding.length}, expected ${expectedDimension}`);
    return false;
  }
  return true;
};