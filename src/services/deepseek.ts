import { logger } from '../utils/logger';

export interface DeepSeekConfig {
  apiKey: string;
  baseURL?: string;
}

export interface DeepSeekRequest {
  model: string;
  messages: Array<{
    role: 'system' | 'user' | 'assistant';
    content: string;
  }>;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop?: string | string[];
  stream?: boolean;
}

export interface DeepSeekResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface DeepSeekModelsResponse {
  object: string;
  data: Array<{
    id: string;
    object: string;
    created: number;
    owned_by: string;
  }>;
}

export class DeepSeekService {
  private apiKey: string;
  private baseURL: string = 'https://api.deepseek.com/v1';

  constructor(config?: DeepSeekConfig) {
    this.apiKey = config?.apiKey || process.env.DEEPSEEK_API_KEY || '';
    this.baseURL = config?.baseURL || this.baseURL;
    
    if (!this.apiKey) {
      logger.warn('DeepSeek API key not provided');
    }
  }

  // Available DeepSeek models
  public models = {
    DEEPSEEK_CHAT: 'deepseek-chat',
    DEEPSEEK_CODER: 'deepseek-coder',
    DEEPSEEK_REASONER: 'deepseek-reasoner',
  };

  async generateCompletion(request: DeepSeekRequest): Promise<DeepSeekResponse> {
    if (!this.apiKey) {
      throw new Error('DeepSeek API key is required');
    }

    const url = `${this.baseURL}/chat/completions`;

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
        throw new Error(`DeepSeek API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      logger.error('DeepSeek API request failed:', error);
      throw new Error(`DeepSeek API request failed: ${error.message}`);
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
    const systemMessage = `You are an expert classic car appraiser and automotive journalist. Generate detailed, engaging descriptions for classic cars that would appeal to collectors, enthusiasts, and investors. Focus on historical significance, technical specifications, performance characteristics, and market appeal.`;

    const userMessage = `Generate a compelling description for this classic car:
- Make: ${vehicle.make}
- Model: ${vehicle.model}
- Year: ${vehicle.year}
- Type: ${vehicle.type || 'Classic Car'}
- Modifications: ${vehicle.modifications || 'None specified'}
- Condition: ${vehicle.condition || 'Not specified'}

Include historical context, performance details, collectibility factors, and market appeal. Keep it under 300 words but make it engaging and informative.`;

    const response = await this.generateCompletion({
      model: this.models.DEEPSEEK_CHAT,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage },
      ],
      temperature: 0.8,
      max_tokens: 500,
    });

    return response.choices[0].message.content;
  }

  async extractVehicleInfo(text: string): Promise<any> {
    const systemMessage = `You are an expert at extracting structured vehicle information from unstructured text. Extract and return vehicle data as a JSON object with standardized fields.`;

    const userMessage = `Extract vehicle information from this text and return as JSON:

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
  "description": string,
  "vin": string,
  "modifications": string,
  "history": string
}`;

    const response = await this.generateCompletion({
      model: this.models.DEEPSEEK_CHAT,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage },
      ],
      temperature: 0.2,
      max_tokens: 800,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse vehicle info JSON:', error);
      return { raw_text: response.choices[0].message.content };
    }
  }

  async generateSearchSuggestions(query: string): Promise<string[]> {
    const systemMessage = `You are a search expert for classic cars and automotive content. Generate relevant search suggestions that would help users find similar or related vehicles, parts, or information.`;

    const userMessage = `Generate 6-8 search suggestions for this classic car query: "${query}"

Return suggestions as a JSON array of strings. Focus on:
- Similar makes/models
- Related years/generations
- Comparable vehicle types
- Popular modifications
- Regional variants
- Parts and accessories
- Market segments

Example format: ["suggestion1", "suggestion2", ...]`;

    const response = await this.generateCompletion({
      model: this.models.DEEPSEEK_CHAT,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage },
      ],
      temperature: 0.7,
      max_tokens: 400,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse search suggestions JSON:', error);
      return [query]; // Fallback to original query
    }
  }

  async classifyVehicle(description: string): Promise<any> {
    const systemMessage = `You are an automotive expert and appraiser. Classify vehicles into detailed categories and provide comprehensive analysis including market positioning, investment potential, and collector appeal.`;

    const userMessage = `Classify this vehicle based on its description:

"${description}"

Return a detailed JSON object with:
{
  "primary_category": "muscle_car|sports_car|luxury|truck|suv|sedan|coupe|convertible|exotic|classic|vintage",
  "sub_category": "specific_type",
  "era": "pre_war|post_war|50s|60s|70s|80s|90s|2000s|modern",
  "market_segment": "entry_level|mid_market|high_end|ultra_luxury|race_car",
  "investment_potential": "low|medium|high|exceptional",
  "rarity_score": number (1-10),
  "collector_appeal": number (1-10),
  "condition_assessment": "excellent|very_good|good|fair|poor|project|unknown",
  "estimated_value_range": "price_range_description",
  "key_selling_points": ["point1", "point2", "point3"],
  "target_buyers": ["buyer_type1", "buyer_type2"],
  "comparable_vehicles": ["vehicle1", "vehicle2"],
  "investment_factors": {
    "appreciation_potential": "low|medium|high",
    "liquidity": "low|medium|high",
    "maintenance_costs": "low|medium|high",
    "parts_availability": "poor|fair|good|excellent"
  }
}`;

    const response = await this.generateCompletion({
      model: this.models.DEEPSEEK_CHAT,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage },
      ],
      temperature: 0.3,
      max_tokens: 1000,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse vehicle classification JSON:', error);
      return { raw_classification: response.choices[0].message.content };
    }
  }

  async generateMarketAnalysis(vehicle: {
    make: string;
    model: string;
    year: number;
    condition?: string;
  }): Promise<any> {
    const systemMessage = `You are a classic car market analyst with expertise in vehicle valuation, market trends, and investment analysis. Provide comprehensive market analysis for classic cars.`;

    const userMessage = `Provide a detailed market analysis for this vehicle:
- Make: ${vehicle.make}
- Model: ${vehicle.model}
- Year: ${vehicle.year}
- Condition: ${vehicle.condition || 'Not specified'}

Return a JSON object with:
{
  "current_market_value": {
    "low": number,
    "average": number,
    "high": number,
    "currency": "USD"
  },
  "market_trends": {
    "6_month_trend": "increasing|stable|decreasing",
    "1_year_trend": "increasing|stable|decreasing",
    "5_year_outlook": "very_positive|positive|neutral|negative"
  },
  "comparable_sales": [
    {
      "description": "brief_description",
      "price": number,
      "date": "YYYY-MM",
      "source": "auction_house_or_marketplace"
    }
  ],
  "investment_score": number (1-100),
  "liquidity_rating": "excellent|good|fair|poor",
  "key_factors": ["factor1", "factor2", "factor3"],
  "risks": ["risk1", "risk2"],
  "opportunities": ["opportunity1", "opportunity2"]
}`;

    const response = await this.generateCompletion({
      model: this.models.DEEPSEEK_REASONER,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage },
      ],
      temperature: 0.4,
      max_tokens: 1200,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse market analysis JSON:', error);
      return { raw_analysis: response.choices[0].message.content };
    }
  }

  async generateRestorationAdvice(vehicle: {
    make: string;
    model: string;
    year: number;
    condition: string;
    description?: string;
  }): Promise<any> {
    const systemMessage = `You are a classic car restoration expert with decades of experience. Provide detailed restoration advice, cost estimates, and project planning guidance.`;

    const userMessage = `Provide restoration advice for this vehicle:
- Make: ${vehicle.make}
- Model: ${vehicle.model}
- Year: ${vehicle.year}
- Condition: ${vehicle.condition}
- Description: ${vehicle.description || 'No additional details'}

Return a JSON object with:
{
  "restoration_category": "concours|driver|survivor|restomod|race_car",
  "estimated_timeline": "time_range",
  "estimated_cost": {
    "low": number,
    "high": number,
    "currency": "USD"
  },
  "priority_areas": ["area1", "area2", "area3"],
  "challenges": ["challenge1", "challenge2"],
  "parts_availability": "excellent|good|fair|poor|very_poor",
  "specialist_requirements": ["requirement1", "requirement2"],
  "roi_potential": "excellent|good|fair|poor",
  "recommendations": ["rec1", "rec2", "rec3"],
  "warning_signs": ["warning1", "warning2"]
}`;

    const response = await this.generateCompletion({
      model: this.models.DEEPSEEK_CODER,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage },
      ],
      temperature: 0.5,
      max_tokens: 1000,
    });

    try {
      return JSON.parse(response.choices[0].message.content);
    } catch (error) {
      logger.error('Failed to parse restoration advice JSON:', error);
      return { raw_advice: response.choices[0].message.content };
    }
  }

  async healthCheck(): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const response = await this.generateCompletion({
        model: this.models.DEEPSEEK_CHAT,
        messages: [
          { role: 'user', content: 'Hello' }
        ],
        max_tokens: 10,
      });
      return !!response.choices[0]?.message?.content;
    } catch (error) {
      logger.error('DeepSeek health check failed:', error);
      return false;
    }
  }

  async getModelInfo(): Promise<DeepSeekModelsResponse> {
    if (!this.apiKey) {
      throw new Error('DeepSeek API key is required');
    }

    try {
      const response = await fetch(`${this.baseURL}/models`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
        },
      });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch models: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      logger.error('Failed to get DeepSeek model info:', error);
      // Return fallback model info
      return {
        object: 'list',
        data: Object.values(this.models).map(model => ({
          id: model,
          object: 'model',
          created: Date.now(),
          owned_by: 'deepseek',
        })),
      };
    }
  }
}

// Export singleton instance
export const deepSeekService = new DeepSeekService();