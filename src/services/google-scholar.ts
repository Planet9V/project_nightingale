import { logger } from '../utils/logger';

export interface GoogleScholarConfig {
  apiKey: string;
  baseURL?: string;
}

export interface ScholarQuery {
  q: string;
  num?: number;
  start?: number;
  year_low?: number;
  year_high?: number;
  sort?: 'relevance' | 'date';
  cluster_id?: string;
  hl?: string; // language
  lr?: string; // language restriction
  safe?: 'active' | 'off';
}

export interface ScholarArticle {
  position: number;
  title: string;
  result_id: string;
  link?: string;
  snippet: string;
  publication_info?: {
    summary: string;
    authors?: Array<{
      name: string;
      link?: string;
      serpapi_scholar_link?: string;
      author_id?: string;
    }>;
  };
  resources?: Array<{
    title: string;
    file_format?: string;
    link: string;
  }>;
  inline_links?: {
    serpapi_cite_link?: string;
    cited_by?: {
      total: number;
      link: string;
      serpapi_scholar_link: string;
    };
    related_pages_link?: string;
    versions?: {
      total: number;
      link: string;
      serpapi_scholar_link: string;
    };
  };
  cited_by?: {
    total: number;
    link: string;
  };
  year?: string;
}

export interface ScholarResponse {
  search_metadata: {
    id: string;
    status: string;
    json_endpoint: string;
    created_at: string;
    processed_at: string;
    google_scholar_url: string;
    raw_html_file: string;
    total_time_taken: number;
  };
  search_parameters: {
    engine: string;
    q: string;
    google_domain: string;
    hl: string;
  };
  search_information: {
    organic_results_state: string;
    query_displayed: string;
    total_results?: number;
    time_taken_displayed?: number;
  };
  organic_results: ScholarArticle[];
  pagination?: {
    current: number;
    next?: string;
    other_pages?: Record<string, string>;
  };
}

export interface VehicleResearchQuery {
  make?: string;
  model?: string;
  year?: number;
  topic?: 'engineering' | 'history' | 'design' | 'performance' | 'market' | 'restoration';
  timeframe?: {
    start?: number;
    end?: number;
  };
}

export class GoogleScholarService {
  private apiKey: string;
  private baseURL: string = 'https://serpapi.com/search';

  constructor(config?: GoogleScholarConfig) {
    this.apiKey = config?.apiKey || process.env.GOOGLE_SCHOLAR_API_KEY || '';
    this.baseURL = config?.baseURL || this.baseURL;
    
    if (!this.apiKey) {
      logger.warn('Google Scholar API key not provided');
    }
  }

  async searchScholar(query: ScholarQuery): Promise<ScholarResponse> {
    if (!this.apiKey) {
      throw new Error('Google Scholar API key is required');
    }

    const params = new URLSearchParams();
    params.append('engine', 'google_scholar');
    params.append('api_key', this.apiKey);
    params.append('q', query.q);
    
    if (query.num) params.append('num', query.num.toString());
    if (query.start) params.append('start', query.start.toString());
    if (query.year_low) params.append('as_ylo', query.year_low.toString());
    if (query.year_high) params.append('as_yhi', query.year_high.toString());
    if (query.sort) params.append('scisbd', query.sort === 'date' ? '1' : '0');
    if (query.cluster_id) params.append('cluster', query.cluster_id);
    if (query.hl) params.append('hl', query.hl);
    if (query.lr) params.append('lr', query.lr);
    if (query.safe) params.append('safe', query.safe);

    const url = `${this.baseURL}?${params.toString()}`;

    try {
      const response = await fetch(url);
      
      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Google Scholar API error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      
      if (data.error) {
        throw new Error(`Google Scholar API error: ${data.error}`);
      }

      return data;
    } catch (error: any) {
      logger.error('Google Scholar request failed:', error);
      throw new Error(`Google Scholar request failed: ${error.message}`);
    }
  }

  // Vehicle-specific research methods
  async searchVehicleResearch(vehicleQuery: VehicleResearchQuery): Promise<ScholarResponse> {
    let searchQuery = '';
    
    if (vehicleQuery.make && vehicleQuery.model) {
      searchQuery = `"${vehicleQuery.make} ${vehicleQuery.model}"`;
      if (vehicleQuery.year) {
        searchQuery += ` "${vehicleQuery.year}"`;
      }
    } else if (vehicleQuery.make) {
      searchQuery = `"${vehicleQuery.make}"`;
    }

    // Add topic-specific terms
    if (vehicleQuery.topic) {
      const topicTerms = {
        engineering: 'engineering design technology innovation automotive',
        history: 'history development evolution timeline automotive industry',
        design: 'design styling aerodynamics aesthetics industrial design',
        performance: 'performance testing analysis evaluation dynamics',
        market: 'market analysis economics valuation investment collector',
        restoration: 'restoration conservation preservation maintenance repair'
      };
      searchQuery += ` AND (${topicTerms[vehicleQuery.topic]})`;
    } else {
      searchQuery += ' AND (automotive OR automobile OR vehicle)';
    }

    // Exclude patents and citations to focus on research papers
    searchQuery += ' -patent -cite';

    const scholarQuery: ScholarQuery = {
      q: searchQuery,
      num: 20,
      sort: 'relevance',
      hl: 'en',
    };

    // Add year range if specified
    if (vehicleQuery.timeframe) {
      if (vehicleQuery.timeframe.start) {
        scholarQuery.year_low = vehicleQuery.timeframe.start;
      }
      if (vehicleQuery.timeframe.end) {
        scholarQuery.year_high = vehicleQuery.timeframe.end;
      }
    }

    return this.searchScholar(scholarQuery);
  }

  async searchAutomotiveEngineering(topic: string): Promise<ScholarResponse> {
    return this.searchScholar({
      q: `automotive engineering "${topic}" AND (design OR development OR innovation OR technology)`,
      num: 15,
      sort: 'relevance',
      hl: 'en',
    });
  }

  async searchClassicCarHistory(make?: string): Promise<ScholarResponse> {
    let query = 'classic car history AND (development OR evolution OR heritage)';
    if (make) {
      query = `"${make}" classic car history AND (heritage OR legacy OR development)`;
    }

    return this.searchScholar({
      q: query,
      num: 20,
      sort: 'relevance',
      hl: 'en',
    });
  }

  async searchAutomotiveMarketResearch(): Promise<ScholarResponse> {
    return this.searchScholar({
      q: 'classic car market analysis AND (valuation OR investment OR collector OR appreciation)',
      num: 15,
      sort: 'date',
      hl: 'en',
      year_low: 2010, // Focus on recent market research
    });
  }

  async searchRestorationTechniques(vehicleType?: string): Promise<ScholarResponse> {
    let query = 'automobile restoration conservation AND (technique OR method OR preservation)';
    if (vehicleType) {
      query = `"${vehicleType}" restoration conservation AND (technique OR method OR process)`;
    }

    return this.searchScholar({
      q: query,
      num: 15,
      sort: 'relevance',
      hl: 'en',
    });
  }

  async searchAutomotiveDesignHistory(era?: string): Promise<ScholarResponse> {
    let query = 'automotive design history AND (styling OR aesthetics OR industrial design)';
    if (era) {
      query += ` AND "${era}"`;
    }

    return this.searchScholar({
      q: query,
      num: 20,
      sort: 'relevance',
      hl: 'en',
    });
  }

  async searchPerformanceAnalysis(vehicleType: string): Promise<ScholarResponse> {
    return this.searchScholar({
      q: `"${vehicleType}" performance analysis AND (dynamics OR testing OR evaluation OR measurement)`,
      num: 15,
      sort: 'relevance',
      hl: 'en',
    });
  }

  async getCitationInfo(resultId: string): Promise<any> {
    if (!this.apiKey) {
      throw new Error('Google Scholar API key is required');
    }

    const params = new URLSearchParams();
    params.append('engine', 'google_scholar_cite');
    params.append('api_key', this.apiKey);
    params.append('q', resultId);

    try {
      const response = await fetch(`${this.baseURL}?${params.toString()}`);
      
      if (!response.ok) {
        throw new Error(`Failed to get citation info: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      logger.error('Failed to get citation info:', error);
      throw error;
    }
  }

  async getAuthorProfile(authorId: string): Promise<any> {
    if (!this.apiKey) {
      throw new Error('Google Scholar API key is required');
    }

    const params = new URLSearchParams();
    params.append('engine', 'google_scholar_author');
    params.append('api_key', this.apiKey);
    params.append('author_id', authorId);

    try {
      const response = await fetch(`${this.baseURL}?${params.toString()}`);
      
      if (!response.ok) {
        throw new Error(`Failed to get author profile: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      logger.error('Failed to get author profile:', error);
      throw error;
    }
  }

  async healthCheck(): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const response = await this.searchScholar({
        q: 'automotive',
        num: 1,
      });
      return !!response.organic_results;
    } catch (error) {
      logger.error('Google Scholar health check failed:', error);
      return false;
    }
  }
}

// Export singleton instance
export const googleScholarService = new GoogleScholarService();