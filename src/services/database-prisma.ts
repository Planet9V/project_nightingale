import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

// Create Prisma client with logging and error handling
export const prisma = new PrismaClient({
  log: [
    {
      emit: 'event',
      level: 'query',
    },
    {
      emit: 'event',
      level: 'error',
    },
    {
      emit: 'event',
      level: 'info',
    },
    {
      emit: 'event',
      level: 'warn',
    },
  ],
  errorFormat: 'pretty',
});

// Log database queries in development
if (process.env.NODE_ENV === 'development') {
  prisma.$on('query', (e) => {
    logger.debug(`Query: ${e.query}`);
    logger.debug(`Params: ${e.params}`);
    logger.debug(`Duration: ${e.duration}ms`);
  });
}

// Log database errors
prisma.$on('error', (e) => {
  logger.error('Database error:', e);
});

// Log database info
prisma.$on('info', (e) => {
  logger.info('Database info:', e.message);
});

// Log database warnings
prisma.$on('warn', (e) => {
  logger.warn('Database warning:', e.message);
});

// Test database connection on startup
export const connectDatabase = async (): Promise<void> => {
  try {
    await prisma.$connect();
    logger.info('✅ Database connected successfully');
    
    // Test query
    await prisma.$queryRaw`SELECT 1 as test`;
    logger.info('✅ Database query test successful');
  } catch (error) {
    logger.error('❌ Database connection failed:', error);
    throw error;
  }
};

// Disconnect database
export const disconnectDatabase = async (): Promise<void> => {
  try {
    await prisma.$disconnect();
    logger.info('🔌 Database disconnected');
  } catch (error) {
    logger.error('❌ Database disconnection failed:', error);
    throw error;
  }
};

// Database health check
export const checkDatabaseHealth = async (): Promise<boolean> => {
  try {
    const start = Date.now();
    await prisma.$queryRaw`SELECT 1 as health_check`;
    const duration = Date.now() - start;
    
    logger.debug(`Database health check completed in ${duration}ms`);
    return true;
  } catch (error) {
    logger.error('Database health check failed:', error);
    return false;
  }
};

// Initialize database connection
connectDatabase().catch((error) => {
  logger.error('Failed to initialize database connection:', error);
  process.exit(1);
});