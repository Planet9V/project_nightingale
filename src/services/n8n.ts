import axios from 'axios';
import { logger } from '../utils/logger';

// n8n Service Integration - Supports local, Tailscale, and cloud instances
export class N8nService {
  private baseURL: string;
  private apiKey?: string;
  private connectionType: 'local' | 'tailscale' | 'network' | 'cloud';

  constructor() {
    // Determine connection type and URL based on environment configuration
    const n8nHost = process.env.N8N_HOST || process.env.N8N_WEBHOOK_URL;
    
    if (n8nHost) {
      // Use explicitly configured host
      this.baseURL = n8nHost.startsWith('http') ? n8nHost : `http://${n8nHost}`;
      
      if (n8nHost.includes('127.0.0.1') || n8nHost.includes('localhost')) {
        this.connectionType = 'local';
      } else if (n8nHost.includes('100.') || n8nHost.includes('.ts.net')) {
        this.connectionType = 'tailscale';
      } else if (n8nHost.includes('192.168.') || n8nHost.includes('10.') || n8nHost.includes('172.')) {
        this.connectionType = 'network';
      } else {
        this.connectionType = 'cloud';
      }
    } else {
      // Default connection preference order
      const connectionPreference = process.env.N8N_CONNECTION_PREFERENCE || 'local,tailscale,network,cloud';
      const preferences = connectionPreference.split(',').map(p => p.trim());
      
      // Try connections in order of preference
      for (const pref of preferences) {
        switch (pref) {
          case 'local':
            if (process.env.N8N_LOCAL_URL) {
              this.baseURL = process.env.N8N_LOCAL_URL;
              this.connectionType = 'local';
              break;
            }
            break;
          case 'tailscale':
            if (process.env.N8N_TAILSCALE_URL) {
              this.baseURL = process.env.N8N_TAILSCALE_URL;
              this.connectionType = 'tailscale';
              break;
            }
            break;
          case 'network':
            if (process.env.N8N_NETWORK_URL) {
              this.baseURL = process.env.N8N_NETWORK_URL;
              this.connectionType = 'network';
              break;
            }
            break;
          case 'cloud':
            if (process.env.N8N_CLOUD_URL) {
              this.baseURL = process.env.N8N_CLOUD_URL;
              this.connectionType = 'cloud';
              break;
            }
            break;
        }
        
        if (this.baseURL) break;
      }
      
      // Fallback to defaults
      if (!this.baseURL) {
        this.baseURL = 'http://127.0.0.1:5678';
        this.connectionType = 'local';
      }
    }
    
    this.apiKey = process.env.N8N_API_KEY;
    
    logger.info(`n8n Service initialized with ${this.connectionType} connection: ${this.baseURL}`);
  }

  // Webhook endpoints for different workflows
  public webhooks = {
    // Data processing workflows
    PROCESS_VEHICLE_DATA: '/webhook/process-vehicle-data',
    EXTRACT_LISTING_INFO: '/webhook/extract-listing-info',
    GENERATE_EMBEDDINGS: '/webhook/generate-embeddings',
    
    // Search and scraping workflows  
    SCRAPE_VEHICLE_LISTINGS: '/webhook/scrape-vehicle-listings',
    SEARCH_EXTERNAL_APIS: '/webhook/search-external-apis',
    AGGREGATE_MARKET_DATA: '/webhook/aggregate-market-data',
    
    // Data transformation workflows
    TRANSFORM_AND_LOAD: '/webhook/transform-and-load',
    CLEAN_VEHICLE_DATA: '/webhook/clean-vehicle-data',
    ENRICH_VEHICLE_INFO: '/webhook/enrich-vehicle-info',
    
    // AI and ML workflows
    GENERATE_DESCRIPTIONS: '/webhook/generate-descriptions',
    CLASSIFY_VEHICLES: '/webhook/classify-vehicles',
    ANALYZE_SENTIMENT: '/webhook/analyze-sentiment',
    
    // Integration workflows
    SYNC_TO_SUPABASE: '/webhook/sync-to-supabase',
    UPDATE_PINECONE: '/webhook/update-pinecone',
    NOTIFY_UPDATES: '/webhook/notify-updates',
  } as const;

  // Generic webhook caller
  async callWebhook(endpoint: string, data: any, options?: {
    timeout?: number;
    retries?: number;
  }): Promise<any> {
    const maxRetries = options?.retries || 3;
    const timeout = options?.timeout || 30000; // 30 seconds

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        logger.info(`Calling n8n webhook: ${endpoint} (attempt ${attempt})`);
        
        const response = await axios.post(
          `${this.baseURL}${endpoint}`,
          data,
          {
            timeout,
            headers: {
              'Content-Type': 'application/json',
              ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` }),
            },
          }
        );

        logger.info(`n8n webhook ${endpoint} completed successfully`);
        return response.data;
      } catch (error: any) {
        logger.error(`n8n webhook ${endpoint} failed (attempt ${attempt}):`, error.message);
        
        if (attempt === maxRetries) {
          throw new Error(`n8n webhook ${endpoint} failed after ${maxRetries} attempts: ${error.message}`);
        }
        
        // Wait before retry (exponential backoff)
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
      }
    }
  }

  // Process vehicle data through n8n workflow
  async processVehicleData(vehicleData: {
    make: string;
    model: string;
    year: number;
    description?: string;
    images?: string[];
    source?: string;
  }): Promise<{
    processed_data: any;
    embeddings?: number[];
    classification?: any;
    enriched_info?: any;
  }> {
    return this.callWebhook(this.webhooks.PROCESS_VEHICLE_DATA, {
      vehicle: vehicleData,
      timestamp: new Date().toISOString(),
    });
  }

  // Scrape vehicle listings from external sources
  async scrapeVehicleListings(params: {
    sources: string[];
    search_criteria: {
      make?: string;
      model?: string;
      year_min?: number;
      year_max?: number;
      price_max?: number;
    };
    max_results?: number;
  }): Promise<{
    listings: any[];
    total_found: number;
    sources_scraped: string[];
  }> {
    return this.callWebhook(this.webhooks.SCRAPE_VEHICLE_LISTINGS, params);
  }

  // Extract and clean listing information
  async extractListingInfo(rawData: {
    url: string;
    html?: string;
    text?: string;
    images?: string[];
  }): Promise<{
    vehicle: any;
    listing: any;
    confidence: number;
  }> {
    return this.callWebhook(this.webhooks.EXTRACT_LISTING_INFO, rawData);
  }

  // Generate embeddings for multiple vehicles
  async generateEmbeddings(vehicles: Array<{
    id: number;
    description: string;
    metadata?: any;
  }>): Promise<{
    embeddings: Array<{
      id: number;
      embedding: number[];
      dimension: number;
    }>;
  }> {
    return this.callWebhook(this.webhooks.GENERATE_EMBEDDINGS, {
      vehicles,
      provider: process.env.EMBEDDING_PROVIDER || 'openai',
    });
  }

  // Transform and load data to Supabase
  async transformAndLoad(data: {
    vehicles?: any[];
    listings?: any[];
    target_table: string;
    operation: 'insert' | 'update' | 'upsert';
  }): Promise<{
    success: boolean;
    processed_count: number;
    errors?: any[];
  }> {
    return this.callWebhook(this.webhooks.TRANSFORM_AND_LOAD, data);
  }

  // Sync processed data to Supabase
  async syncToSupabase(data: {
    table: string;
    records: any[];
    operation: 'insert' | 'update' | 'upsert';
  }): Promise<{
    success: boolean;
    inserted: number;
    updated: number;
    errors?: any[];
  }> {
    return this.callWebhook(this.webhooks.SYNC_TO_SUPABASE, data);
  }

  // Update Pinecone vectors
  async updatePinecone(data: {
    index: string;
    namespace: string;
    vectors: Array<{
      id: string;
      values: number[];
      metadata?: any;
    }>;
  }): Promise<{
    success: boolean;
    upserted_count: number;
  }> {
    return this.callWebhook(this.webhooks.UPDATE_PINECONE, data);
  }

  // Aggregate market data from multiple sources
  async aggregateMarketData(params: {
    make?: string;
    model?: string;
    year_range?: [number, number];
    sources?: string[];
  }): Promise<{
    average_price: number;
    price_range: [number, number];
    market_trend: 'increasing' | 'decreasing' | 'stable';
    data_points: number;
    last_updated: string;
  }> {
    return this.callWebhook(this.webhooks.AGGREGATE_MARKET_DATA, params);
  }

  // Generate AI descriptions for vehicles
  async generateDescriptions(vehicles: Array<{
    id: number;
    make: string;
    model: string;
    year: number;
    features?: string[];
    modifications?: string[];
  }>): Promise<{
    descriptions: Array<{
      id: number;
      description: string;
      highlights: string[];
    }>;
  }> {
    return this.callWebhook(this.webhooks.GENERATE_DESCRIPTIONS, { vehicles });
  }

  // Classify vehicles using AI
  async classifyVehicles(vehicles: Array<{
    id: number;
    description: string;
    make?: string;
    model?: string;
    year?: number;
  }>): Promise<{
    classifications: Array<{
      id: number;
      type: string;
      category: string;
      era: string;
      value_category: string;
      confidence: number;
    }>;
  }> {
    return this.callWebhook(this.webhooks.CLASSIFY_VEHICLES, { vehicles });
  }

  // Clean and normalize vehicle data
  async cleanVehicleData(rawVehicles: any[]): Promise<{
    cleaned_vehicles: any[];
    validation_errors: any[];
    duplicate_count: number;
  }> {
    return this.callWebhook(this.webhooks.CLEAN_VEHICLE_DATA, {
      vehicles: rawVehicles,
    });
  }

  // Enrich vehicle information with external data
  async enrichVehicleInfo(vehicles: Array<{
    id: number;
    make: string;
    model: string;
    year: number;
  }>): Promise<{
    enriched_vehicles: Array<{
      id: number;
      specifications?: any;
      historical_info?: any;
      market_value?: any;
      similar_vehicles?: any[];
    }>;
  }> {
    return this.callWebhook(this.webhooks.ENRICH_VEHICLE_INFO, { vehicles });
  }

  // Send notifications about updates
  async notifyUpdates(notification: {
    type: 'new_listings' | 'price_changes' | 'system_alert';
    data: any;
    recipients?: string[];
  }): Promise<{
    success: boolean;
    sent_count: number;
  }> {
    return this.callWebhook(this.webhooks.NOTIFY_UPDATES, notification);
  }

  // Health check for n8n service with connection type awareness
  async healthCheck(): Promise<{ healthy: boolean; connectionType: string; url: string }> {
    try {
      // Different endpoints for different n8n deployment types
      const healthEndpoints = [
        '/healthz',
        '/api/v1/health',
        '/webhook/health',
        '/', // Basic connectivity check
      ];
      
      for (const endpoint of healthEndpoints) {
        try {
          const response = await axios.get(`${this.baseURL}${endpoint}`, {
            timeout: 5000,
            headers: this.apiKey ? { 'Authorization': `Bearer ${this.apiKey}` } : {},
          });
          
          if (response.status === 200 || response.status === 404) {
            // 404 is ok - it means n8n is responding but endpoint doesn't exist
            logger.info(`n8n health check successful via ${this.connectionType} at ${this.baseURL}`);
            return {
              healthy: true,
              connectionType: this.connectionType,
              url: this.baseURL,
            };
          }
        } catch (endpointError) {
          // Try next endpoint
          continue;
        }
      }
      
      throw new Error('All health check endpoints failed');
    } catch (error) {
      logger.warn(`n8n health check failed for ${this.connectionType} connection at ${this.baseURL}`);
      return {
        healthy: false,
        connectionType: this.connectionType,
        url: this.baseURL,
      };
    }
  }
  
  // Get current connection info
  getConnectionInfo(): { type: string; url: string; hasApiKey: boolean } {
    return {
      type: this.connectionType,
      url: this.baseURL,
      hasApiKey: !!this.apiKey,
    };
  }

  // Get workflow status (requires API key)
  async getWorkflowStatus(workflowId?: string): Promise<any> {
    if (!this.apiKey) {
      throw new Error('n8n API key required for workflow status');
    }

    try {
      const url = workflowId 
        ? `${this.baseURL}/api/v1/workflows/${workflowId}`
        : `${this.baseURL}/api/v1/workflows`;

      const response = await axios.get(url, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
        },
      });

      return response.data;
    } catch (error) {
      logger.error('Failed to get n8n workflow status:', error);
      throw error;
    }
  }
}

// Export singleton instance
export const n8nService = new N8nService();

// Convenience functions for common operations
export const processAndStoreVehicle = async (vehicleData: any) => {
  try {
    // Step 1: Process vehicle data through n8n
    const processed = await n8nService.processVehicleData(vehicleData);
    
    // Step 2: Store in Supabase
    await n8nService.syncToSupabase({
      table: 'vehicles',
      records: [processed.processed_data],
      operation: 'upsert',
    });
    
    // Step 3: Store embeddings in Pinecone
    if (processed.embeddings) {
      await n8nService.updatePinecone({
        index: 'vehicle-vectors',
        namespace: 'descriptions',
        vectors: [{
          id: `vehicle_${processed.processed_data.id}_desc`,
          values: processed.embeddings,
          metadata: processed.processed_data,
        }],
      });
    }
    
    return processed.processed_data;
  } catch (error) {
    logger.error('Failed to process and store vehicle:', error);
    throw error;
  }
};

export const bulkProcessListings = async (listings: any[]) => {
  try {
    // Process in batches to avoid timeouts
    const batchSize = 10;
    const results = [];
    
    for (let i = 0; i < listings.length; i += batchSize) {
      const batch = listings.slice(i, i + batchSize);
      
      // Clean and enrich data
      const cleaned = await n8nService.cleanVehicleData(batch);
      const enriched = await n8nService.enrichVehicleInfo(cleaned.cleaned_vehicles);
      
      // Generate embeddings and store
      const processed = await Promise.all(
        enriched.enriched_vehicles.map(vehicle => processAndStoreVehicle(vehicle))
      );
      
      results.push(...processed);
      
      // Brief pause between batches
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    return results;
  } catch (error) {
    logger.error('Failed to bulk process listings:', error);
    throw error;
  }
};