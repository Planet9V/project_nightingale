import { logger } from '../utils/logger';

// Simple in-memory cache for development and lightweight deployments
class InMemoryCache {
  private cache: Map<string, { data: any; expires: number }> = new Map();
  private maxSize: number = 1000; // Maximum number of cache entries

  set(key: string, value: any, ttlSeconds: number = 1800): void {
    try {
      // Remove oldest entries if cache is getting too large
      if (this.cache.size >= this.maxSize) {
        const oldestKey = this.cache.keys().next().value;
        this.cache.delete(oldestKey);
      }

      const expires = Date.now() + (ttlSeconds * 1000);
      this.cache.set(key, { data: value, expires });
      
      logger.debug(`Cached item with key: ${key} for ${ttlSeconds} seconds`);
    } catch (error) {
      logger.error(`Failed to cache item with key ${key}:`, error);
    }
  }

  get(key: string): any | null {
    try {
      const item = this.cache.get(key);
      
      if (!item) {
        logger.debug(`Cache miss for key: ${key}`);
        return null;
      }

      if (Date.now() > item.expires) {
        this.cache.delete(key);
        logger.debug(`Cache expired for key: ${key}`);
        return null;
      }

      logger.debug(`Cache hit for key: ${key}`);
      return item.data;
    } catch (error) {
      logger.error(`Failed to get cached item with key ${key}:`, error);
      return null;
    }
  }

  delete(key: string): void {
    try {
      this.cache.delete(key);
      logger.debug(`Deleted cache item with key: ${key}`);
    } catch (error) {
      logger.error(`Failed to delete cache item with key ${key}:`, error);
    }
  }

  clear(): void {
    try {
      this.cache.clear();
      logger.info('Cache cleared');
    } catch (error) {
      logger.error('Failed to clear cache:', error);
    }
  }

  getStats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
    };
  }

  // Clean up expired entries
  cleanup(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, item] of this.cache.entries()) {
      if (now > item.expires) {
        this.cache.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug(`Cleaned up ${cleanedCount} expired cache entries`);
    }
  }
}

// Create cache instance
const cache = new InMemoryCache();

// Run cleanup every 5 minutes
setInterval(() => {
  cache.cleanup();
}, 5 * 60 * 1000);

// Cache key prefixes
export const CACHE_KEYS = {
  VEHICLE: 'vehicle:',
  LISTING: 'listing:',
  MARKET_DATA: 'market:',
  USER_SESSION: 'session:',
  SEARCH_RESULTS: 'search:',
  PRICE_ALERTS: 'alerts:',
  EVENT_DATA: 'event:',
  ANALYTICS: 'analytics:',
  NEWS: 'news:',
  RESEARCH: 'research:',
  AI_RESPONSE: 'ai:',
} as const;

// Cache TTL values (in seconds)
export const CACHE_TTL = {
  SHORT: 300, // 5 minutes
  MEDIUM: 1800, // 30 minutes
  LONG: 3600, // 1 hour
  EXTENDED: 86400, // 24 hours
  PERMANENT: -1, // No expiration (use with caution)
} as const;

// Helper function to check if caching is enabled
const isCachingEnabled = (): boolean => {
  return process.env.ENABLE_CACHING === 'true';
};

// Vehicle caching functions
export const cacheVehicle = (vehicleId: number, vehicleData: any, ttl: number = CACHE_TTL.MEDIUM): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.VEHICLE}${vehicleId}`;
  cache.set(key, vehicleData, ttl);
};

export const getCachedVehicle = (vehicleId: number): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.VEHICLE}${vehicleId}`;
  return cache.get(key);
};

// Listing caching functions
export const cacheListing = (listingId: number, listingData: any, ttl: number = CACHE_TTL.SHORT): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.LISTING}${listingId}`;
  cache.set(key, listingData, ttl);
};

export const getCachedListing = (listingId: number): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.LISTING}${listingId}`;
  return cache.get(key);
};

// Market data caching
export const cacheMarketData = (key: string, data: any, ttl: number = CACHE_TTL.LONG): void => {
  if (!isCachingEnabled()) return;
  
  const cacheKey = `${CACHE_KEYS.MARKET_DATA}${key}`;
  cache.set(cacheKey, data, ttl);
};

export const getCachedMarketData = (key: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const cacheKey = `${CACHE_KEYS.MARKET_DATA}${key}`;
  return cache.get(cacheKey);
};

// Search results caching
export const cacheSearchResults = (searchKey: string, results: any, ttl: number = CACHE_TTL.MEDIUM): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.SEARCH_RESULTS}${searchKey}`;
  cache.set(key, results, ttl);
};

export const getCachedSearchResults = (searchKey: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.SEARCH_RESULTS}${searchKey}`;
  return cache.get(key);
};

// News caching
export const cacheNews = (newsKey: string, data: any, ttl: number = CACHE_TTL.MEDIUM): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.NEWS}${newsKey}`;
  cache.set(key, data, ttl);
};

export const getCachedNews = (newsKey: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.NEWS}${newsKey}`;
  return cache.get(key);
};

// Research caching
export const cacheResearch = (researchKey: string, data: any, ttl: number = CACHE_TTL.LONG): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.RESEARCH}${researchKey}`;
  cache.set(key, data, ttl);
};

export const getCachedResearch = (researchKey: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.RESEARCH}${researchKey}`;
  return cache.get(key);
};

// AI response caching
export const cacheAIResponse = (requestKey: string, response: any, ttl: number = CACHE_TTL.LONG): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.AI_RESPONSE}${requestKey}`;
  cache.set(key, response, ttl);
};

export const getCachedAIResponse = (requestKey: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.AI_RESPONSE}${requestKey}`;
  return cache.get(key);
};

// Session management (lightweight alternative)
export const storeUserSession = (sessionId: string, userData: any, ttl: number = CACHE_TTL.EXTENDED): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.USER_SESSION}${sessionId}`;
  cache.set(key, userData, ttl);
};

export const getUserSession = (sessionId: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.USER_SESSION}${sessionId}`;
  return cache.get(key);
};

export const deleteUserSession = (sessionId: string): void => {
  const key = `${CACHE_KEYS.USER_SESSION}${sessionId}`;
  cache.delete(key);
};

// Analytics caching
export const cacheAnalytics = (analyticsKey: string, data: any, ttl: number = CACHE_TTL.EXTENDED): void => {
  if (!isCachingEnabled()) return;
  
  const key = `${CACHE_KEYS.ANALYTICS}${analyticsKey}`;
  cache.set(key, data, ttl);
};

export const getCachedAnalytics = (analyticsKey: string): any | null => {
  if (!isCachingEnabled()) return null;
  
  const key = `${CACHE_KEYS.ANALYTICS}${analyticsKey}`;
  return cache.get(key);
};

// Utility functions
export const invalidateCache = (pattern: string): void => {
  // Simple pattern matching - could be enhanced
  logger.info(`Cache invalidation requested for pattern: ${pattern}`);
  cache.clear(); // For simplicity, clear all cache
};

export const getCacheStats = (): any => {
  return {
    enabled: isCachingEnabled(),
    ...cache.getStats(),
    type: 'in-memory',
  };
};

// Health check
export const checkCacheHealth = (): boolean => {
  try {
    // Test cache functionality
    const testKey = 'health_check_test';
    const testValue = { timestamp: Date.now() };
    
    cache.set(testKey, testValue, 1);
    const retrieved = cache.get(testKey);
    cache.delete(testKey);
    
    return retrieved !== null && retrieved.timestamp === testValue.timestamp;
  } catch (error) {
    logger.error('Cache health check failed:', error);
    return false;
  }
};

export default cache;