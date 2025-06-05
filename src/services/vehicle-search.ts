import { logger } from '../utils/logger';
import { 
  storeVehicleDescriptionEmbedding, 
  searchSimilarVehiclesByDescription,
  storeVehicleImageEmbedding,
  searchSimilarVehiclesByImage
} from './pinecone';
import { generateEmbedding, generateImageEmbedding } from './embeddings';
import { prisma } from './database';

// Index a vehicle's description for semantic search
export const indexVehicleDescription = async (vehicleId: number): Promise<void> => {
  try {
    // Fetch vehicle data
    const vehicle = await prisma.vehicle.findUnique({
      where: { id: vehicleId },
      include: {
        modifications: true,
        listings: {
          where: { isActive: true },
          take: 1,
        },
      },
    });

    if (!vehicle) {
      throw new Error(`Vehicle ${vehicleId} not found`);
    }

    // Create rich text description for embedding
    const description = [
      `${vehicle.year} ${vehicle.make} ${vehicle.model}`,
      vehicle.vehicleType && `Type: ${vehicle.vehicleType}`,
      vehicle.bodyStyle && `Body: ${vehicle.bodyStyle}`,
      vehicle.engineType && `Engine: ${vehicle.engineType} ${vehicle.engineSize || ''}`,
      vehicle.transmission && `Transmission: ${vehicle.transmission}`,
      vehicle.colorExterior && `Color: ${vehicle.colorExterior}`,
      vehicle.description,
      vehicle.modifications.length > 0 && 
        `Modifications: ${vehicle.modifications.map(m => m.description).join(', ')}`,
      vehicle.listings[0]?.price && 
        `Price: $${vehicle.listings[0].price.toLocaleString()}`,
    ].filter(Boolean).join('. ');

    logger.info(`Generating embedding for vehicle ${vehicleId}: ${description.substring(0, 100)}...`);

    // Generate embedding
    const embedding = await generateEmbedding(description, 'description');

    // Store in Pinecone with metadata
    await storeVehicleDescriptionEmbedding(vehicleId, embedding, {
      make: vehicle.make,
      model: vehicle.model,
      year: vehicle.year,
      type: vehicle.vehicleType,
      price: vehicle.listings[0]?.price || 0,
      location: vehicle.listings[0]?.location || 'Unknown',
      has_modifications: vehicle.modifications.length > 0,
      indexed_at: new Date().toISOString(),
    });

    logger.info(`✅ Indexed vehicle ${vehicleId} successfully`);
  } catch (error) {
    logger.error(`Failed to index vehicle ${vehicleId}:`, error);
    throw error;
  }
};

// Search for similar vehicles using natural language
export const searchVehicles = async (
  query: string,
  filters?: {
    make?: string;
    yearMin?: number;
    yearMax?: number;
    priceMax?: number;
    type?: string;
  },
  limit: number = 10
): Promise<any[]> => {
  try {
    logger.info(`Searching for vehicles with query: "${query}"`);

    // Generate embedding for the search query
    const queryEmbedding = await generateEmbedding(query, 'search');

    // Search in Pinecone
    const results = await searchSimilarVehiclesByDescription(
      queryEmbedding,
      limit * 2, // Get more results for filtering
      0.5 // Lower threshold for broader results
    );

    // Apply additional filters if provided
    let filteredResults = results;
    if (filters) {
      filteredResults = results.filter(result => {
        const metadata = result.metadata;
        if (filters.make && metadata?.make !== filters.make) return false;
        if (filters.yearMin && metadata?.year < filters.yearMin) return false;
        if (filters.yearMax && metadata?.year > filters.yearMax) return false;
        if (filters.priceMax && metadata?.price > filters.priceMax) return false;
        if (filters.type && metadata?.type !== filters.type) return false;
        return true;
      });
    }

    // Fetch full vehicle data
    const vehicleIds = filteredResults
      .slice(0, limit)
      .map(r => r.vehicleId)
      .filter(Boolean);

    const vehicles = await prisma.vehicle.findMany({
      where: { id: { in: vehicleIds } },
      include: {
        images: { take: 1 },
        listings: { where: { isActive: true }, take: 1 },
        modifications: true,
      },
    });

    // Combine with similarity scores
    return vehicles.map(vehicle => {
      const result = filteredResults.find(r => r.vehicleId === vehicle.id);
      return {
        ...vehicle,
        similarity_score: result?.score || 0,
        search_metadata: result?.metadata,
      };
    }).sort((a, b) => b.similarity_score - a.similarity_score);

  } catch (error) {
    logger.error('Failed to search vehicles:', error);
    throw error;
  }
};

// Index all vehicles (for initial setup or reindexing)
export const indexAllVehicles = async (batchSize: number = 10): Promise<void> => {
  try {
    const totalVehicles = await prisma.vehicle.count();
    logger.info(`Starting to index ${totalVehicles} vehicles...`);

    let processed = 0;
    let cursor: number | undefined;

    while (processed < totalVehicles) {
      const vehicles = await prisma.vehicle.findMany({
        take: batchSize,
        skip: cursor ? 1 : 0,
        ...(cursor && { cursor: { id: cursor } }),
        orderBy: { id: 'asc' },
      });

      if (vehicles.length === 0) break;

      // Process vehicles in parallel
      await Promise.all(
        vehicles.map(vehicle => 
          indexVehicleDescription(vehicle.id).catch(error => {
            logger.error(`Failed to index vehicle ${vehicle.id}:`, error);
          })
        )
      );

      processed += vehicles.length;
      cursor = vehicles[vehicles.length - 1].id;

      logger.info(`Indexed ${processed}/${totalVehicles} vehicles (${Math.round(processed / totalVehicles * 100)}%)`);
    }

    logger.info('✅ Finished indexing all vehicles');
  } catch (error) {
    logger.error('Failed to index all vehicles:', error);
    throw error;
  }
};

// Example usage for image similarity search
export const indexVehicleImage = async (
  vehicleId: number,
  imageId: string,
  imageBuffer: Buffer,
  mimeType: string
): Promise<void> => {
  try {
    // Generate image embedding (requires multimodal model)
    const embedding = await generateImageEmbedding(imageBuffer, mimeType);

    // Store in Pinecone
    await storeVehicleImageEmbedding(vehicleId, imageId, embedding, {
      mime_type: mimeType,
      indexed_at: new Date().toISOString(),
    });

    logger.info(`✅ Indexed image ${imageId} for vehicle ${vehicleId}`);
  } catch (error) {
    logger.error(`Failed to index image for vehicle ${vehicleId}:`, error);
    throw error;
  }
};

// Find visually similar vehicles
export const findSimilarVehiclesByImage = async (
  imageBuffer: Buffer,
  mimeType: string,
  limit: number = 10
): Promise<any[]> => {
  try {
    // Generate embedding for the query image
    const queryEmbedding = await generateImageEmbedding(imageBuffer, mimeType);

    // Search in Pinecone
    const results = await searchSimilarVehiclesByImage(queryEmbedding, limit);

    // Fetch vehicle data
    const vehicleIds = [...new Set(results.map(r => r.vehicleId).filter(Boolean))];
    
    const vehicles = await prisma.vehicle.findMany({
      where: { id: { in: vehicleIds } },
      include: {
        images: true,
        listings: { where: { isActive: true }, take: 1 },
      },
    });

    return vehicles;
  } catch (error) {
    logger.error('Failed to find similar vehicles by image:', error);
    throw error;
  }
};