import axios from 'axios';
import { logger } from '../utils/logger';

// OpenRouter service for chat completions and multiple AI models
export class OpenRouterService {
  private apiKey: string;
  private baseURL = 'https://openrouter.ai/api/v1';

  constructor() {
    this.apiKey = process.env.OPENROUTER_API_KEY || '';
    if (!this.apiKey) {
      logger.warn('OpenRouter API key not configured');
    }
  }

  // Available models on OpenRouter
  public models = {
    // OpenAI models
    GPT_4_TURBO: 'openai/gpt-4-turbo',
    GPT_4: 'openai/gpt-4',
    GPT_3_5_TURBO: 'openai/gpt-3.5-turbo',
    
    // Anthropic models
    CLAUDE_3_OPUS: 'anthropic/claude-3-opus',
    CLAUDE_3_SONNET: 'anthropic/claude-3-sonnet',
    CLAUDE_3_HAIKU: 'anthropic/claude-3-haiku',
    
    // Google models
    GEMINI_PRO: 'google/gemini-pro',
    GEMINI_PRO_VISION: 'google/gemini-pro-vision',
    
    // Meta models
    LLAMA_2_70B: 'meta-llama/llama-2-70b-chat',
    LLAMA_3_8B: 'meta-llama/llama-3-8b-instruct',
    
    // Mistral models
    MISTRAL_LARGE: 'mistralai/mistral-large',
    MISTRAL_MEDIUM: 'mistralai/mistral-medium',
    
    // Cohere models
    COMMAND_R_PLUS: 'cohere/command-r-plus',
    COMMAND_R: 'cohere/command-r',
  } as const;

  // Chat completion with any model
  async chatCompletion(params: {
    model: string;
    messages: Array<{
      role: 'system' | 'user' | 'assistant';
      content: string;
    }>;
    temperature?: number;
    max_tokens?: number;
    stream?: boolean;
  }) {
    try {
      if (!this.apiKey) {
        throw new Error('OpenRouter API key not configured');
      }

      const response = await axios.post(
        `${this.baseURL}/chat/completions`,
        {
          model: params.model,
          messages: params.messages,
          temperature: params.temperature || 0.7,
          max_tokens: params.max_tokens || 1000,
          stream: params.stream || false,
        },
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': process.env.FRONTEND_URL || 'http://localhost:3000',
            'X-Title': 'Classic Cars AI Backend',
          },
        }
      );

      return response.data;
    } catch (error: any) {
      logger.error('OpenRouter chat completion failed:', error.response?.data || error.message);
      throw error;
    }
  }

  // Generate vehicle description using AI
  async generateVehicleDescription(vehicle: {
    make: string;
    model: string;
    year: number;
    type?: string;
    modifications?: string[];
    condition?: string;
  }): Promise<string> {
    const messages = [
      {
        role: 'system' as const,
        content: 'You are an expert classic car appraiser and writer. Generate engaging, detailed vehicle descriptions for classic car listings that highlight key features, historical significance, and appeal to collectors.',
      },
      {
        role: 'user' as const,
        content: `Write a compelling description for this classic car:
        
Year: ${vehicle.year}
Make: ${vehicle.make}
Model: ${vehicle.model}
Type: ${vehicle.type || 'Classic'}
Condition: ${vehicle.condition || 'Well-maintained'}
Modifications: ${vehicle.modifications?.join(', ') || 'Stock'}

Include historical context, key features, and collector appeal. Keep it under 200 words.`,
      },
    ];

    const response = await this.chatCompletion({
      model: this.models.GPT_3_5_TURBO,
      messages,
      temperature: 0.8,
      max_tokens: 300,
    });

    return response.choices[0].message.content;
  }

  // Extract vehicle information from text
  async extractVehicleInfo(text: string): Promise<{
    make?: string;
    model?: string;
    year?: number;
    price?: number;
    features?: string[];
    condition?: string;
  }> {
    const messages = [
      {
        role: 'system' as const,
        content: 'Extract vehicle information from text and return it as JSON. Return null for missing fields.',
      },
      {
        role: 'user' as const,
        content: `Extract vehicle details from this text: "${text}"
        
Return JSON with fields: make, model, year, price, features (array), condition`,
      },
    ];

    const response = await this.chatCompletion({
      model: this.models.GPT_3_5_TURBO,
      messages,
      temperature: 0.1,
      max_tokens: 200,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse vehicle extraction response:', error);
      return {};
    }
  }

  // Generate search query suggestions
  async generateSearchSuggestions(query: string): Promise<string[]> {
    const messages = [
      {
        role: 'system' as const,
        content: 'Generate 5 related search suggestions for classic car searches. Return as JSON array of strings.',
      },
      {
        role: 'user' as const,
        content: `Generate search suggestions related to: "${query}"`,
      },
    ];

    const response = await this.chatCompletion({
      model: this.models.GPT_3_5_TURBO,
      messages,
      temperature: 0.7,
      max_tokens: 150,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse search suggestions:', error);
      return [];
    }
  }

  // Classify vehicle type and category
  async classifyVehicle(description: string): Promise<{
    type: string;
    category: string;
    era: string;
    value_category: string;
  }> {
    const messages = [
      {
        role: 'system' as const,
        content: 'Classify vehicles into categories. Return JSON with fields: type (classic/restomod/hot_rod/original), category (car/truck/motorcycle), era (pre_war/post_war/muscle_car/modern_classic), value_category (economy/mid_range/premium/exotic).',
      },
      {
        role: 'user' as const,
        content: `Classify this vehicle: "${description}"`,
      },
    ];

    const response = await this.chatCompletion({
      model: this.models.GPT_3_5_TURBO,
      messages,
      temperature: 0.1,
      max_tokens: 100,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse vehicle classification:', error);
      return {
        type: 'classic',
        category: 'car',
        era: 'post_war',
        value_category: 'mid_range',
      };
    }
  }

  // Get model information and pricing
  async getModelInfo(): Promise<any> {
    try {
      const response = await axios.get(`${this.baseURL}/models`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
        },
      });
      return response.data;
    } catch (error) {
      logger.error('Failed to get OpenRouter models:', error);
      throw error;
    }
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      if (!this.apiKey) return false;
      
      await this.getModelInfo();
      return true;
    } catch (error) {
      return false;
    }
  }
}

// Export singleton instance
export const openRouterService = new OpenRouterService();