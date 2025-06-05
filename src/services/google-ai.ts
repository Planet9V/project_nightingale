import { logger } from '../utils/logger';

export interface GoogleAIConfig {
  apiKey: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface GoogleAIRequest {
  prompt: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  systemInstruction?: string;
}

export interface GoogleAIResponse {
  text: string;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  model: string;
}

export class GoogleAIService {
  private apiKey: string;
  private baseURL: string = 'https://generativelanguage.googleapis.com/v1beta';
  private defaultModel: string = 'gemini-pro';

  constructor(config?: GoogleAIConfig) {
    this.apiKey = config?.apiKey || process.env.GOOGLE_AI_API_KEY || '';
    if (!this.apiKey) {
      logger.warn('Google AI API key not provided');
    }
  }

  // Available Gemini models
  public models = {
    GEMINI_PRO: 'gemini-pro',
    GEMINI_PRO_VISION: 'gemini-pro-vision',
    GEMINI_1_5_PRO: 'gemini-1.5-pro',
    GEMINI_1_5_FLASH: 'gemini-1.5-flash',
    GEMINI_1_5_FLASH_8B: 'gemini-1.5-flash-8b',
  };

  async generateText(request: GoogleAIRequest): Promise<GoogleAIResponse> {
    if (!this.apiKey) {
      throw new Error('Google AI API key is required');
    }

    const model = request.model || this.defaultModel;
    const url = `${this.baseURL}/models/${model}:generateContent?key=${this.apiKey}`;

    const payload = {
      contents: [
        {
          parts: [
            {
              text: request.systemInstruction 
                ? `${request.systemInstruction}\n\n${request.prompt}`
                : request.prompt
            }
          ]
        }
      ],
      generationConfig: {
        temperature: request.temperature || 0.7,
        maxOutputTokens: request.maxTokens || 1000,
        topP: 0.8,
        topK: 40,
      },
    };

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Google AI API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      
      if (!data.candidates || !data.candidates[0]?.content?.parts?.[0]?.text) {
        throw new Error('Invalid response format from Google AI');
      }

      return {
        text: data.candidates[0].content.parts[0].text,
        usage: data.usageMetadata ? {
          prompt_tokens: data.usageMetadata.promptTokenCount || 0,
          completion_tokens: data.usageMetadata.candidatesTokenCount || 0,
          total_tokens: data.usageMetadata.totalTokenCount || 0,
        } : undefined,
        model,
      };
    } catch (error: any) {
      logger.error('Google AI generation failed:', error);
      throw new Error(`Google AI request failed: ${error.message}`);
    }
  }

  // Vehicle-specific methods
  async generateVehicleDescription(vehicle: {
    make: string;
    model: string;
    year: number;
    type?: string;
    modifications?: string;
    condition?: string;
  }): Promise<string> {
    const systemInstruction = `You are an expert classic car appraiser and writer. Generate detailed, engaging descriptions for classic cars that would appeal to collectors and enthusiasts. Focus on historical significance, performance characteristics, and investment potential.`;

    const prompt = `Generate a compelling description for this classic car:
- Make: ${vehicle.make}
- Model: ${vehicle.model}
- Year: ${vehicle.year}
- Type: ${vehicle.type || 'Classic Car'}
- Modifications: ${vehicle.modifications || 'None specified'}
- Condition: ${vehicle.condition || 'Not specified'}

Include historical context, performance details, and market appeal. Keep it under 300 words.`;

    const response = await this.generateText({
      prompt,
      systemInstruction,
      model: this.models.GEMINI_1_5_FLASH,
      temperature: 0.8,
    });

    return response.text;
  }

  async extractVehicleInfo(text: string): Promise<any> {
    const systemInstruction = `You are an expert at extracting structured vehicle information from unstructured text. Return a JSON object with the extracted data.`;

    const prompt = `Extract vehicle information from this text and return as JSON:

"${text}"

Return a JSON object with these fields (use null for missing data):
{
  "make": string,
  "model": string,
  "year": number,
  "color": string,
  "mileage": number,
  "engine": string,
  "transmission": string,
  "price": number,
  "location": string,
  "condition": string,
  "description": string
}`;

    const response = await this.generateText({
      prompt,
      systemInstruction,
      model: this.models.GEMINI_1_5_FLASH,
      temperature: 0.3,
    });

    try {
      return JSON.parse(response.text);
    } catch (error) {
      logger.error('Failed to parse vehicle info JSON:', error);
      return { raw_text: response.text };
    }
  }

  async generateSearchSuggestions(query: string): Promise<string[]> {
    const systemInstruction = `You are a search expert for classic cars. Generate 5-8 related search suggestions that would help users find similar or related vehicles.`;

    const prompt = `Generate search suggestions for this classic car query: "${query}"

Return suggestions as a JSON array of strings. Focus on:
- Similar makes/models
- Related years/generations
- Comparable vehicle types
- Popular modifications
- Regional variants

Example format: ["suggestion1", "suggestion2", ...]`;

    const response = await this.generateText({
      prompt,
      systemInstruction,
      model: this.models.GEMINI_1_5_FLASH,
      temperature: 0.7,
    });

    try {
      return JSON.parse(response.text);
    } catch (error) {
      logger.error('Failed to parse search suggestions JSON:', error);
      return [query]; // Fallback to original query
    }
  }

  async classifyVehicle(description: string): Promise<any> {
    const systemInstruction = `You are an automotive expert. Classify vehicles into categories and provide detailed analysis.`;

    const prompt = `Classify this vehicle based on its description:

"${description}"

Return a JSON object with:
{
  "category": "muscle_car|sports_car|luxury|truck|suv|sedan|coupe|convertible|exotic|classic",
  "era": "pre_war|post_war|60s|70s|80s|90s|2000s|modern",
  "investment_potential": "low|medium|high|exceptional",
  "rarity": "common|uncommon|rare|very_rare|one_of_a_kind",
  "market_segment": "entry_level|mid_market|high_end|ultra_luxury",
  "collector_appeal": number (1-10),
  "estimated_value_range": "price_range_string",
  "key_features": ["feature1", "feature2"],
  "target_audience": ["collector_type1", "collector_type2"]
}`;

    const response = await this.generateText({
      prompt,
      systemInstruction,
      model: this.models.GEMINI_1_5_FLASH,
      temperature: 0.4,
    });

    try {
      return JSON.parse(response.text);
    } catch (error) {
      logger.error('Failed to parse vehicle classification JSON:', error);
      return { raw_classification: response.text };
    }
  }

  async healthCheck(): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const response = await this.generateText({
        prompt: 'Hello',
        model: this.models.GEMINI_1_5_FLASH,
        maxTokens: 10,
      });
      return !!response.text;
    } catch (error) {
      logger.error('Google AI health check failed:', error);
      return false;
    }
  }

  async getModelInfo(): Promise<any> {
    try {
      const url = `${this.baseURL}/models?key=${this.apiKey}`;
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch models: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      logger.error('Failed to get Google AI model info:', error);
      return { models: Object.values(this.models) };
    }
  }
}

// Export singleton instance
export const googleAIService = new GoogleAIService();