/**
 * NOTE: This file needs to be updated to use the new Supabase database service
 * The Prisma calls have been commented out and need to be replaced with
 * appropriate Supabase database calls using the 'db' service from './database'
 * 
 * Migration Date: 2025-06-13T04:44:31.265Z
 */

import { logger } from '../utils/logger';
import { 
  storeVehicleDescriptionEmbedding, 
  searchSimilarVehiclesByDescription,
  storeVehicleImageEmbedding,
  searchSimilarVehiclesByImage
} from './pinecone';
import { generateEmbedding, generateImageEmbedding } from './embeddings';
import { db } from './database';

// Index a vehicle's description for semantic search
export const indexVehicleDescription = async (vehicleId: number): Promise<void> => {
  try {
    // Fetch vehicle data
    const { data: vehicle, error } = await db
      .from('vehicles')
      .select(`
        *,
        modifications (*),
        listings!inner (
          *
        )
      `)
      .eq('id', vehicleId)
      .eq('listings.isActive', true)
      .limit(1, { foreignTable: 'listings' })
      .single();

    if (error) {
      throw new Error(`Failed to fetch vehicle ${vehicleId}: ${error.message}`);
    }

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

    const { data: vehicles, error } = await db
      .from('vehicles')
      .select(`
        *,
        images (*),
        listings!inner (*),
        modifications (*)
      `)
      .in('id', vehicleIds)
      .eq('listings.isActive', true)
      .limit(1, { foreignTable: 'images' })
      .limit(1, { foreignTable: 'listings' });

    if (error) {
      throw new Error(`Failed to fetch vehicles: ${error.message}`);
    }

    if (!vehicles) {
      return [];
    }

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
    const { count: totalVehicles, error: countError } = await db
      .from('vehicles')
      .select('*', { count: 'exact', head: true });

    if (countError) {
      throw new Error(`Failed to count vehicles: ${countError.message}`);
    }

    if (!totalVehicles) {
      logger.info('No vehicles found to index');
      return;
    }
    logger.info(`Starting to index ${totalVehicles} vehicles...`);

    let processed = 0;
    let cursor: number | undefined;

    while (processed < totalVehicles) {
      const { data: vehicles, error } = await db
        .from('vehicles')
        .select('*')
        .order('id', { ascending: true })
        .range(processed, processed + batchSize - 1);

      if (error) {
        throw new Error(`Failed to fetch vehicles batch: ${error.message}`);
      }

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
      // No cursor needed with range-based pagination

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
    
    const { data: vehicles, error } = await db
      .from('vehicles')
      .select(`
        *,
        images (*),
        listings!inner (*)
      `)
      .in('id', vehicleIds)
      .eq('listings.isActive', true)
      .limit(1, { foreignTable: 'listings' });

    if (error) {
      throw new Error(`Failed to fetch vehicles by image: ${error.message}`);
    }

    return vehicles;
  } catch (error) {
    logger.error('Failed to find similar vehicles by image:', error);
    throw error;
  }
};