import { logger } from '../utils/logger';

export interface TavilyConfig {
  apiKey: string;
  baseURL?: string;
}

export interface TavilySearchRequest {
  query: string;
  search_depth?: 'basic' | 'advanced';
  include_answer?: boolean;
  include_images?: boolean;
  include_raw_content?: boolean;
  max_results?: number;
  include_domains?: string[];
  exclude_domains?: string[];
  format?: 'json' | 'markdown';
  days?: number;
}

export interface TavilySearchResult {
  title: string;
  url: string;
  content: string;
  raw_content?: string;
  score: number;
  published_date?: string;
}

export interface TavilySearchResponse {
  query: string;
  follow_up_questions?: string[];
  answer?: string;
  images?: string[];
  results: TavilySearchResult[];
  response_time: number;
}

export interface VehicleSearchQuery {
  make?: string;
  model?: string;
  year?: number;
  searchType?: 'listings' | 'specifications' | 'reviews' | 'history' | 'market' | 'parts';
  priceRange?: {
    min?: number;
    max?: number;
  };
  location?: string;
}

export class TavilyService {
  private apiKey: string;
  private baseURL: string = 'https://api.tavily.com';

  constructor(config?: TavilyConfig) {
    this.apiKey = config?.apiKey || process.env.TAVILY_API_KEY || '';
    this.baseURL = config?.baseURL || this.baseURL;
    
    if (!this.apiKey) {
      logger.warn('Tavily API key not provided');
    }
  }

  async search(request: TavilySearchRequest): Promise<TavilySearchResponse> {
    if (!this.apiKey) {
      throw new Error('Tavily API key is required');
    }

    const url = `${this.baseURL}/search`;

    const payload = {
      api_key: this.apiKey,
      query: request.query,
      search_depth: request.search_depth || 'basic',
      include_answer: request.include_answer ?? true,
      include_images: request.include_images ?? false,
      include_raw_content: request.include_raw_content ?? false,
      max_results: request.max_results || 10,
      include_domains: request.include_domains,
      exclude_domains: request.exclude_domains,
      format: request.format || 'json',
      days: request.days,
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
        throw new Error(`Tavily API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      logger.error('Tavily search request failed:', error);
      throw new Error(`Tavily search request failed: ${error.message}`);
    }
  }

  // Vehicle-specific search methods
  async searchVehicle(vehicleQuery: VehicleSearchQuery): Promise<TavilySearchResponse> {
    let searchQuery = '';
    
    if (vehicleQuery.make && vehicleQuery.model) {
      searchQuery = `${vehicleQuery.make} ${vehicleQuery.model}`;
      if (vehicleQuery.year) {
        searchQuery += ` ${vehicleQuery.year}`;
      }
    } else if (vehicleQuery.make) {
      searchQuery = vehicleQuery.make;
    }

    // Add search type specific terms
    if (vehicleQuery.searchType) {
      const searchTypeTerms = {
        listings: 'for sale buy listing marketplace',
        specifications: 'specifications specs technical details engine',
        reviews: 'review test drive opinion comparison',
        history: 'history heritage development timeline',
        market: 'market value price trend investment',
        parts: 'parts accessories restoration OEM aftermarket'
      };
      searchQuery += ` ${searchTypeTerms[vehicleQuery.searchType]}`;
    }

    // Add price range if specified
    if (vehicleQuery.priceRange) {
      if (vehicleQuery.priceRange.min && vehicleQuery.priceRange.max) {
        searchQuery += ` price $${vehicleQuery.priceRange.min} to $${vehicleQuery.priceRange.max}`;
      } else if (vehicleQuery.priceRange.max) {
        searchQuery += ` under $${vehicleQuery.priceRange.max}`;
      }
    }

    // Add location if specified
    if (vehicleQuery.location) {
      searchQuery += ` in ${vehicleQuery.location}`;
    }

    const domains = this.getRelevantDomains(vehicleQuery.searchType);

    return this.search({
      query: searchQuery,
      search_depth: 'advanced',
      include_answer: true,
      max_results: 15,
      include_domains: domains,
    });
  }

  async searchVehicleListings(make: string, model: string, year?: number): Promise<TavilySearchResponse> {
    let query = `${make} ${model}`;
    if (year) query += ` ${year}`;
    query += ' for sale classic car listing marketplace';

    return this.search({
      query,
      search_depth: 'advanced',
      include_answer: false,
      max_results: 20,
      include_domains: [
        'classiccars.com',
        'hemmings.com',
        'autotrader.com',
        'cars.com',
        'bringatrailer.com',
        'dupontregistry.com',
        'classic.com',
        'barrett-jackson.com',
        'rmsothebys.com',
        'bonhams.com',
      ],
    });
  }

  async searchVehicleSpecs(make: string, model: string, year?: number): Promise<TavilySearchResponse> {
    let query = `${make} ${model}`;
    if (year) query += ` ${year}`;
    query += ' specifications technical specs engine performance';

    return this.search({
      query,
      search_depth: 'basic',
      include_answer: true,
      max_results: 10,
      include_domains: [
        'edmunds.com',
        'motortrend.com',
        'caranddriver.com',
        'roadandtrack.com',
        'autoweek.com',
        'wikipedia.org',
        'conceptcarz.com',
        'supercars.net',
      ],
    });
  }

  async searchMarketData(make: string, model: string, year?: number): Promise<TavilySearchResponse> {
    let query = `${make} ${model}`;
    if (year) query += ` ${year}`;
    query += ' market value price trend hagerty classic car valuation';

    return this.search({
      query,
      search_depth: 'advanced',
      include_answer: true,
      max_results: 12,
      include_domains: [
        'hagerty.com',
        'classiccars.com',
        'hemmings.com',
        'collectorcarnation.com',
        'classic.com',
        'barrett-jackson.com',
        'rmsothebys.com',
        'bonhams.com',
      ],
    });
  }

  async searchVehicleHistory(make: string, model: string): Promise<TavilySearchResponse> {
    const query = `${make} ${model} history heritage development timeline classic car`;

    return this.search({
      query,
      search_depth: 'basic',
      include_answer: true,
      max_results: 10,
      include_domains: [
        'wikipedia.org',
        'conceptcarz.com',
        'supercars.net',
        'autoweek.com',
        'hemmings.com',
        'motortrend.com',
        'roadandtrack.com',
      ],
    });
  }

  async searchRestorationInfo(make: string, model: string, year?: number): Promise<TavilySearchResponse> {
    let query = `${make} ${model}`;
    if (year) query += ` ${year}`;
    query += ' restoration guide parts sources technical information';

    return this.search({
      query,
      search_depth: 'advanced',
      include_answer: true,
      max_results: 15,
      include_domains: [
        'hemmings.com',
        'classiccars.com',
        'motortrend.com',
        'hotrod.com',
        'streetmusclemag.com',
        'musclecarresearch.com',
      ],
    });
  }

  async searchAuctionResults(make?: string, model?: string): Promise<TavilySearchResponse> {
    let query = 'classic car auction results recent sales';
    if (make && model) {
      query = `${make} ${model} auction results sold prices`;
    } else if (make) {
      query = `${make} auction results classic car sales`;
    }

    return this.search({
      query,
      search_depth: 'advanced',
      include_answer: false,
      max_results: 20,
      include_domains: [
        'barrett-jackson.com',
        'rmsothebys.com',
        'bonhams.com',
        'mecum.com',
        'gooding.com',
        'worldwideauctioneers.com',
        'classiccars.com',
        'bringatrailer.com',
      ],
      days: 365, // Last year's results
    });
  }

  async searchNews(query: string): Promise<TavilySearchResponse> {
    return this.search({
      query: `${query} classic car automotive news`,
      search_depth: 'basic',
      include_answer: true,
      max_results: 15,
      include_domains: [
        'autoweek.com',
        'motortrend.com',
        'caranddriver.com',
        'roadandtrack.com',
        'classiccars.com',
        'hemmings.com',
        'autoblog.com',
        'jalopnik.com',
        'topgear.com',
      ],
      days: 30, // Recent news
    });
  }

  async searchComparableVehicles(make: string, model: string, year?: number): Promise<TavilySearchResponse> {
    let query = `similar to ${make} ${model}`;
    if (year) query += ` ${year}`;
    query += ' comparable classic cars alternatives';

    return this.search({
      query,
      search_depth: 'basic',
      include_answer: true,
      max_results: 10,
    });
  }

  private getRelevantDomains(searchType?: string): string[] {
    const domainSets = {
      listings: [
        'classiccars.com',
        'hemmings.com',
        'autotrader.com',
        'cars.com',
        'bringatrailer.com',
        'dupontregistry.com',
        'classic.com',
      ],
      specifications: [
        'edmunds.com',
        'motortrend.com',
        'caranddriver.com',
        'roadandtrack.com',
        'autoweek.com',
        'conceptcarz.com',
      ],
      reviews: [
        'motortrend.com',
        'caranddriver.com',
        'roadandtrack.com',
        'autoweek.com',
        'topgear.com',
      ],
      history: [
        'conceptcarz.com',
        'supercars.net',
        'autoweek.com',
        'hemmings.com',
        'motortrend.com',
      ],
      market: [
        'hagerty.com',
        'classiccars.com',
        'hemmings.com',
        'collectorcarnation.com',
        'classic.com',
      ],
      parts: [
        'hemmings.com',
        'classiccars.com',
        'autopartswarehouse.com',
        'summitracing.com',
      ],
    };

    return searchType ? domainSets[searchType as keyof typeof domainSets] || [] : [];
  }

  async healthCheck(): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const response = await this.search({
        query: 'classic car',
        max_results: 1,
      });
      return !!response.results && response.results.length > 0;
    } catch (error) {
      logger.error('Tavily health check failed:', error);
      return false;
    }
  }
}

// Export singleton instance
export const tavilyService = new TavilyService();