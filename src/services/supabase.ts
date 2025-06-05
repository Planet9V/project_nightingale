import { createClient } from '@supabase/supabase-js';
import { logger } from '../utils/logger';

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Public client for client-side operations
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: false,
  },
});

// Admin client for server-side operations with full privileges
export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});

// Storage bucket names
export const STORAGE_BUCKETS = {
  PUBLIC: 'med-public', // Main public bucket from Supabase configuration
  VEHICLE_IMAGES: 'vehicle-images',
  USER_AVATARS: 'user-avatars',
  DOCUMENTS: 'documents',
} as const;

// Initialize storage buckets
export const initializeSupabaseStorage = async (): Promise<void> => {
  try {
    logger.info('🔄 Initializing Supabase storage buckets...');

    for (const [key, bucketName] of Object.entries(STORAGE_BUCKETS)) {
      const { data: existingBucket } = await supabaseAdmin.storage
        .getBucket(bucketName);

      if (!existingBucket) {
        const { error } = await supabaseAdmin.storage.createBucket(bucketName, {
          public: bucketName !== STORAGE_BUCKETS.DOCUMENTS, // Documents are private
          fileSizeLimit: 10485760, // 10MB
          allowedMimeTypes: bucketName === STORAGE_BUCKETS.VEHICLE_IMAGES
            ? ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
            : bucketName === STORAGE_BUCKETS.USER_AVATARS
            ? ['image/jpeg', 'image/png', 'image/webp']
            : undefined, // No restrictions for documents
        });

        if (error) {
          logger.error(`Failed to create bucket '${bucketName}':`, error);
        } else {
          logger.info(`✅ Created storage bucket '${bucketName}'`);
        }
      } else {
        logger.info(`📦 Storage bucket '${bucketName}' already exists`);
      }
    }

    logger.info('✅ Supabase storage initialized successfully');
  } catch (error) {
    logger.error('❌ Failed to initialize Supabase storage:', error);
    throw error;
  }
};

// Upload vehicle image
export const uploadVehicleImage = async (
  vehicleId: number,
  file: Buffer,
  fileName: string,
  mimeType: string
): Promise<string | null> => {
  try {
    const filePath = `${vehicleId}/${Date.now()}-${fileName}`;
    
    const { data, error } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.VEHICLE_IMAGES)
      .upload(filePath, file, {
        contentType: mimeType,
        upsert: false,
      });

    if (error) {
      logger.error(`Failed to upload vehicle image:`, error);
      return null;
    }

    // Get public URL
    const { data: urlData } = supabaseAdmin.storage
      .from(STORAGE_BUCKETS.VEHICLE_IMAGES)
      .getPublicUrl(filePath);

    logger.debug(`Uploaded vehicle image for vehicle ${vehicleId}: ${filePath}`);
    return urlData.publicUrl;
  } catch (error) {
    logger.error(`Error uploading vehicle image:`, error);
    return null;
  }
};

// Delete vehicle images
export const deleteVehicleImages = async (vehicleId: number): Promise<void> => {
  try {
    const { data: files } = await supabaseAdmin.storage
      .from(STORAGE_BUCKETS.VEHICLE_IMAGES)
      .list(`${vehicleId}/`);

    if (files && files.length > 0) {
      const filePaths = files.map(file => `${vehicleId}/${file.name}`);
      
      const { error } = await supabaseAdmin.storage
        .from(STORAGE_BUCKETS.VEHICLE_IMAGES)
        .remove(filePaths);

      if (error) {
        logger.error(`Failed to delete vehicle images:`, error);
      } else {
        logger.info(`Deleted ${filePaths.length} images for vehicle ${vehicleId}`);
      }
    }
  } catch (error) {
    logger.error(`Error deleting vehicle images:`, error);
  }
};

// Health check for Supabase
export const checkSupabaseHealth = async (): Promise<boolean> => {
  try {
    const start = Date.now();
    
    // Try to get the authenticated user (should fail with anon key, but connection works)
    const { error } = await supabase.auth.getUser();
    
    const duration = Date.now() - start;
    logger.debug(`Supabase health check completed in ${duration}ms`);
    
    // If we get an auth error, it means the connection is working
    return true;
  } catch (error) {
    logger.error('Supabase health check failed:', error);
    return false;
  }
};

// Initialize Supabase on startup (only storage, as database is managed by Prisma)
initializeSupabaseStorage().catch((error) => {
  logger.error('Failed to initialize Supabase storage:', error);
  // Don't exit process as storage is not critical for basic functionality
});