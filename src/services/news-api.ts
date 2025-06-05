import { logger } from '../utils/logger';

export interface NewsAPIConfig {
  apiKey: string;
  baseURL?: string;
}

export interface NewsQuery {
  q?: string;
  sources?: string;
  domains?: string;
  excludeDomains?: string;
  from?: string;
  to?: string;
  language?: string;
  sortBy?: 'relevancy' | 'popularity' | 'publishedAt';
  pageSize?: number;
  page?: number;
}

export interface NewsArticle {
  source: {
    id: string | null;
    name: string;
  };
  author: string | null;
  title: string;
  description: string | null;
  url: string;
  urlToImage: string | null;
  publishedAt: string;
  content: string | null;
}

export interface NewsResponse {
  status: string;
  totalResults: number;
  articles: NewsArticle[];
}

export interface VehicleNewsQuery {
  make?: string;
  model?: string;
  year?: number;
  category?: 'classic' | 'muscle' | 'sports' | 'luxury' | 'auction' | 'market';
  timeframe?: 'day' | 'week' | 'month' | 'year';
}

export class NewsAPIService {
  private apiKey: string;
  private baseURL: string = 'https://newsapi.org/v2';

  constructor(config?: NewsAPIConfig) {
    this.apiKey = config?.apiKey || process.env.NEWSAPI_KEY || '';
    this.baseURL = config?.baseURL || this.baseURL;
    
    if (!this.apiKey) {
      logger.warn('NewsAPI key not provided');
    }
  }

  async searchNews(query: NewsQuery): Promise<NewsResponse> {
    if (!this.apiKey) {
      throw new Error('NewsAPI key is required');
    }

    const params = new URLSearchParams();
    params.append('apiKey', this.apiKey);
    
    if (query.q) params.append('q', query.q);
    if (query.sources) params.append('sources', query.sources);
    if (query.domains) params.append('domains', query.domains);
    if (query.excludeDomains) params.append('excludeDomains', query.excludeDomains);
    if (query.from) params.append('from', query.from);
    if (query.to) params.append('to', query.to);
    if (query.language) params.append('language', query.language);
    if (query.sortBy) params.append('sortBy', query.sortBy);
    if (query.pageSize) params.append('pageSize', query.pageSize.toString());
    if (query.page) params.append('page', query.page.toString());

    const url = `${this.baseURL}/everything?${params.toString()}`;

    try {
      const response = await fetch(url);
      
      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`NewsAPI error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      
      if (data.status === 'error') {
        throw new Error(`NewsAPI error: ${data.message}`);
      }

      return data;
    } catch (error: any) {
      logger.error('NewsAPI request failed:', error);
      throw new Error(`NewsAPI request failed: ${error.message}`);
    }
  }

  async getTopHeadlines(query: Omit<NewsQuery, 'q'> & { q?: string; country?: string; category?: string }): Promise<NewsResponse> {
    if (!this.apiKey) {
      throw new Error('NewsAPI key is required');
    }

    const params = new URLSearchParams();
    params.append('apiKey', this.apiKey);
    
    if (query.q) params.append('q', query.q);
    if (query.sources) params.append('sources', query.sources);
    if (query.domains) params.append('domains', query.domains);
    if ((query as any).country) params.append('country', (query as any).country);
    if ((query as any).category) params.append('category', (query as any).category);
    if (query.pageSize) params.append('pageSize', query.pageSize.toString());
    if (query.page) params.append('page', query.page.toString());

    const url = `${this.baseURL}/top-headlines?${params.toString()}`;

    try {
      const response = await fetch(url);
      
      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`NewsAPI error: ${response.status} - ${errorData}`);
      }

      const data = await response.json();
      
      if (data.status === 'error') {
        throw new Error(`NewsAPI error: ${data.message}`);
      }

      return data;
    } catch (error: any) {
      logger.error('NewsAPI top headlines request failed:', error);
      throw new Error(`NewsAPI request failed: ${error.message}`);
    }
  }

  // Vehicle-specific news methods
  async getVehicleNews(vehicleQuery: VehicleNewsQuery): Promise<NewsResponse> {
    let searchQuery = '';
    
    if (vehicleQuery.make && vehicleQuery.model) {
      searchQuery = `"${vehicleQuery.make} ${vehicleQuery.model}"`;
      if (vehicleQuery.year) {
        searchQuery += ` "${vehicleQuery.year}"`;
      }
    } else if (vehicleQuery.make) {
      searchQuery = `"${vehicleQuery.make}"`;
    }

    // Add category-specific terms
    if (vehicleQuery.category) {
      const categoryTerms = {
        classic: 'classic car vintage collector',
        muscle: 'muscle car performance V8',
        sports: 'sports car racing track',
        luxury: 'luxury car premium exotic',
        auction: 'auction sale barrett-jackson rm sotheby',
        market: 'market value price investment'
      };
      searchQuery += ` AND (${categoryTerms[vehicleQuery.category]})`;
    } else {
      searchQuery += ' AND (car automobile vehicle classic collector)';
    }

    // Set timeframe
    let from = '';
    if (vehicleQuery.timeframe) {
      const now = new Date();
      const timeframes = {
        day: 1,
        week: 7,
        month: 30,
        year: 365
      };
      const daysBack = timeframes[vehicleQuery.timeframe];
      const fromDate = new Date(now.getTime() - (daysBack * 24 * 60 * 60 * 1000));
      from = fromDate.toISOString().split('T')[0];
    }

    return this.searchNews({
      q: searchQuery,
      domains: 'motor1.com,autoweek.com,classiccars.com,hemmings.com,roadandtrack.com,caranddriver.com,motortrend.com,autoblog.com,jalopnik.com,topgear.com',
      language: 'en',
      sortBy: 'relevancy',
      pageSize: 20,
      from,
    });
  }

  async getClassicCarMarketNews(): Promise<NewsResponse> {
    return this.searchNews({
      q: '("classic car" OR "collector car") AND (auction OR market OR investment OR value OR price)',
      domains: 'classiccars.com,hemmings.com,barrett-jackson.com,rmsothebys.com,bonhams.com,autoweek.com,hagerty.com',
      language: 'en',
      sortBy: 'publishedAt',
      pageSize: 25,
    });
  }

  async getAuctionNews(): Promise<NewsResponse> {
    return this.searchNews({
      q: '("car auction" OR "auto auction") AND (barrett-jackson OR rm OR sotheby OR bonhams OR mecum OR gooding)',
      language: 'en',
      sortBy: 'publishedAt',
      pageSize: 20,
    });
  }

  async getManufacturerNews(manufacturer: string): Promise<NewsResponse> {
    return this.searchNews({
      q: `"${manufacturer}" AND (classic OR vintage OR collector OR restoration OR heritage)`,
      language: 'en',
      sortBy: 'relevancy',
      pageSize: 15,
    });
  }

  async getNewsByCategory(category: 'restoration' | 'racing' | 'shows' | 'investment'): Promise<NewsResponse> {
    const categoryQueries = {
      restoration: '("car restoration" OR "classic car restoration" OR "vintage restoration") AND (project OR rebuild OR original)',
      racing: '("classic racing" OR "vintage racing" OR "historic racing") AND (motorsport OR track OR competition)',
      shows: '("car show" OR "auto show" OR "concours") AND (classic OR vintage OR collector)',
      investment: '("classic car investment" OR "collector car market") AND (value OR appreciation OR portfolio)'
    };

    return this.searchNews({
      q: categoryQueries[category],
      language: 'en',
      sortBy: 'relevancy',
      pageSize: 20,
    });
  }

  async healthCheck(): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const response = await this.getTopHeadlines({
        q: 'car',
        pageSize: 1,
      });
      return response.status === 'ok';
    } catch (error) {
      logger.error('NewsAPI health check failed:', error);
      return false;
    }
  }

  async getSources(): Promise<any> {
    if (!this.apiKey) {
      throw new Error('NewsAPI key is required');
    }

    try {
      const response = await fetch(`${this.baseURL}/sources?apiKey=${this.apiKey}&category=general&language=en`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch sources: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      logger.error('Failed to get NewsAPI sources:', error);
      throw error;
    }
  }
}

// Export singleton instance
export const newsAPIService = new NewsAPIService();