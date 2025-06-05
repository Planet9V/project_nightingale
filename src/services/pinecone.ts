import { Pinecone, Index, RecordMetadata } from '@pinecone-database/pinecone';
import { logger } from '../utils/logger';

// Initialize Pinecone client lazily
// Organization: Mckenney Engineers
// Project: MED_Infrastructure
let pinecone: Pinecone | null = null;

const getPineconeClient = (): Pinecone => {
  if (!pinecone) {
    const apiKey = process.env.PINECONE_API_KEY;
    if (!apiKey) {
      throw new Error('PINECONE_API_KEY environment variable is required');
    }
    pinecone = new Pinecone({ apiKey });
  }
  return pinecone;
};

// Index names for different vector types
export const INDEXES = {
  VEHICLE_VECTORS: 'vehicle-vectors',
  USER_VECTORS: 'user-vectors',
  MARKET_VECTORS: 'market-vectors',
} as const;

// Namespaces within indexes
export const NAMESPACES = {
  DESCRIPTIONS: 'descriptions',
  IMAGES: 'images',
  MODIFICATIONS: 'modifications',
  PREFERENCES: 'preferences',
  TRENDS: 'trends',
} as const;

// Vector dimensions for different embedding types
export const VECTOR_DIMENSIONS = {
  DESCRIPTION: 768, // OpenAI text-embedding-ada-002 or similar
  IMAGE: 512, // Image embedding dimension
  MODIFICATION: 256, // Custom modification embeddings
  MARKET_POSITION: 128, // Market position embeddings
  USER_PREFERENCE: 512, // User preference embeddings
} as const;

// Lazy index getters
const getVehicleIndex = (): Index<RecordMetadata> => getPineconeClient().index(INDEXES.VEHICLE_VECTORS);
const getUserIndex = (): Index<RecordMetadata> => getPineconeClient().index(INDEXES.USER_VECTORS);
const getMarketIndex = (): Index<RecordMetadata> => getPineconeClient().index(INDEXES.MARKET_VECTORS);

// Initialize Pinecone indexes
export const initializePineconeIndexes = async (): Promise<void> => {
  try {
    logger.info('🔄 Initializing Pinecone indexes...');

    const client = getPineconeClient();

    // Get list of existing indexes
    const existingIndexes = await client.listIndexes();
    const indexNames = existingIndexes.indexes?.map(idx => idx.name) || [];

    // Create vehicle vectors index if it doesn't exist
    if (!indexNames.includes(INDEXES.VEHICLE_VECTORS)) {
      await client.createIndex({
        name: INDEXES.VEHICLE_VECTORS,
        dimension: VECTOR_DIMENSIONS.DESCRIPTION,
        metric: 'cosine',
        spec: {
          serverless: {
            cloud: 'aws',
            region: 'us-east-1',
          },
        },
      });
      logger.info(`✅ Created index '${INDEXES.VEHICLE_VECTORS}'`);
    }

    // Create user vectors index if it doesn't exist
    if (!indexNames.includes(INDEXES.USER_VECTORS)) {
      await client.createIndex({
        name: INDEXES.USER_VECTORS,
        dimension: VECTOR_DIMENSIONS.USER_PREFERENCE,
        metric: 'cosine',
        spec: {
          serverless: {
            cloud: 'aws',
            region: 'us-east-1',
          },
        },
      });
      logger.info(`✅ Created index '${INDEXES.USER_VECTORS}'`);
    }

    // Create market vectors index if it doesn't exist
    if (!indexNames.includes(INDEXES.MARKET_VECTORS)) {
      await client.createIndex({
        name: INDEXES.MARKET_VECTORS,
        dimension: VECTOR_DIMENSIONS.MARKET_POSITION,
        metric: 'cosine',
        spec: {
          serverless: {
            cloud: 'aws',
            region: 'us-east-1',
          },
        },
      });
      logger.info(`✅ Created index '${INDEXES.MARKET_VECTORS}'`);
    }

    // Wait for indexes to be ready
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Index references are now lazy - no need to store them

    logger.info('✅ Pinecone indexes initialized successfully');
  } catch (error) {
    logger.error('❌ Failed to initialize Pinecone indexes:', error);
    throw error;
  }
};

// Store vehicle description embedding
export const storeVehicleDescriptionEmbedding = async (
  vehicleId: number,
  embedding: number[],
  metadata: Record<string, any>
): Promise<string> => {
  try {
    const id = `vehicle_${vehicleId}_desc`;
    
    await getVehicleIndex().namespace(NAMESPACES.DESCRIPTIONS).upsert([
      {
        id,
        values: embedding,
        metadata: {
          vehicle_id: vehicleId,
          type: 'description',
          ...metadata,
        },
      },
    ]);

    logger.debug(`Stored description embedding for vehicle ${vehicleId}`);
    return id;
  } catch (error) {
    logger.error(`Failed to store description embedding for vehicle ${vehicleId}:`, error);
    throw error;
  }
};

// Store vehicle image embedding
export const storeVehicleImageEmbedding = async (
  vehicleId: number,
  imageId: string,
  embedding: number[],
  metadata: Record<string, any>
): Promise<string> => {
  try {
    const id = `vehicle_${vehicleId}_img_${imageId}`;
    
    await getVehicleIndex().namespace(NAMESPACES.IMAGES).upsert([
      {
        id,
        values: embedding,
        metadata: {
          vehicle_id: vehicleId,
          image_id: imageId,
          type: 'image',
          ...metadata,
        },
      },
    ]);

    logger.debug(`Stored image embedding for vehicle ${vehicleId}, image ${imageId}`);
    return id;
  } catch (error) {
    logger.error(`Failed to store image embedding for vehicle ${vehicleId}:`, error);
    throw error;
  }
};

// Search similar vehicles by description
export const searchSimilarVehiclesByDescription = async (
  queryEmbedding: number[],
  limit: number = 10,
  threshold: number = 0.7
) => {
  try {
    const queryResponse = await getVehicleIndex()
      .namespace(NAMESPACES.DESCRIPTIONS)
      .query({
        vector: queryEmbedding,
        topK: limit,
        includeMetadata: true,
        includeValues: false,
      });

    return queryResponse.matches
      ?.filter(match => match.score && match.score >= threshold)
      .map(match => ({
        vehicleId: match.metadata?.vehicle_id,
        score: match.score,
        metadata: match.metadata,
      })) || [];
  } catch (error) {
    logger.error('Failed to search similar vehicles by description:', error);
    throw error;
  }
};

// Search similar vehicles by image
export const searchSimilarVehiclesByImage = async (
  queryEmbedding: number[],
  limit: number = 10,
  threshold: number = 0.7
) => {
  try {
    const queryResponse = await getVehicleIndex()
      .namespace(NAMESPACES.IMAGES)
      .query({
        vector: queryEmbedding,
        topK: limit,
        includeMetadata: true,
        includeValues: false,
      });

    return queryResponse.matches
      ?.filter(match => match.score && match.score >= threshold)
      .map(match => ({
        vehicleId: match.metadata?.vehicle_id,
        imageId: match.metadata?.image_id,
        score: match.score,
        metadata: match.metadata,
      })) || [];
  } catch (error) {
    logger.error('Failed to search similar vehicles by image:', error);
    throw error;
  }
};

// Store user preference embedding
export const storeUserPreferenceEmbedding = async (
  userId: number,
  embedding: number[],
  metadata: Record<string, any>
): Promise<string> => {
  try {
    const id = `user_${userId}_pref`;
    
    await getUserIndex().namespace(NAMESPACES.PREFERENCES).upsert([
      {
        id,
        values: embedding,
        metadata: {
          user_id: userId,
          type: 'preference',
          ...metadata,
        },
      },
    ]);

    logger.debug(`Stored preference embedding for user ${userId}`);
    return id;
  } catch (error) {
    logger.error(`Failed to store preference embedding for user ${userId}:`, error);
    throw error;
  }
};

// Get personalized vehicle recommendations
export const getPersonalizedRecommendations = async (
  userId: number,
  limit: number = 20
) => {
  try {
    // First, fetch the user's preference embedding
    const userVectors = await getUserIndex()
      .namespace(NAMESPACES.PREFERENCES)
      .fetch([`user_${userId}_pref`]);

    const userRecord = userVectors.records[`user_${userId}_pref`];
    if (!userRecord || !userRecord.values) {
      logger.warn(`No preference embedding found for user ${userId}`);
      return [];
    }

    // Search for similar vehicles using user preference vector
    return await searchSimilarVehiclesByDescription(userRecord.values, limit, 0.6);
  } catch (error) {
    logger.error(`Failed to get personalized recommendations for user ${userId}:`, error);
    throw error;
  }
};

// Store market trend embedding
export const storeMarketTrendEmbedding = async (
  trendId: string,
  embedding: number[],
  metadata: Record<string, any>
): Promise<string> => {
  try {
    const id = `trend_${trendId}`;
    
    await getMarketIndex().namespace(NAMESPACES.TRENDS).upsert([
      {
        id,
        values: embedding,
        metadata: {
          trend_id: trendId,
          type: 'market_trend',
          ...metadata,
        },
      },
    ]);

    logger.debug(`Stored market trend embedding for ${trendId}`);
    return id;
  } catch (error) {
    logger.error(`Failed to store market trend embedding for ${trendId}:`, error);
    throw error;
  }
};

// Health check for Pinecone
export const checkPineconeHealth = async (): Promise<boolean> => {
  try {
    const start = Date.now();
    const indexes = await getPineconeClient().listIndexes();
    const duration = Date.now() - start;
    
    logger.debug(`Pinecone health check completed in ${duration}ms`);
    return indexes.indexes !== undefined;
  } catch (error) {
    logger.error('Pinecone health check failed:', error);
    return false;
  }
};

// Delete vectors for a specific vehicle
export const deleteVehicleVectors = async (vehicleId: number): Promise<void> => {
  try {
    // Delete from descriptions namespace
    await getVehicleIndex()
      .namespace(NAMESPACES.DESCRIPTIONS)
      .deleteOne(`vehicle_${vehicleId}_desc`);

    // Delete from images namespace (would need to fetch all image IDs first)
    // This is a simplified version - in production, you'd want to track image IDs
    logger.info(`Deleted vectors for vehicle ${vehicleId}`);
  } catch (error) {
    logger.error(`Failed to delete vectors for vehicle ${vehicleId}:`, error);
    throw error;
  }
};

// Initialize Pinecone on startup (when environment is loaded)
// Call initializePineconeIndexes() explicitly when needed