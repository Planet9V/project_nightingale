import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { Pinecone } from '@pinecone-database/pinecone';
import neo4j, { Driver, Session } from 'neo4j-driver';
import { S3Client, HeadBucketCommand } from '@aws-sdk/client-s3';
import { logger } from '../utils/logger';
import axios from 'axios';

export interface HealthCheckResult {
  service: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  latency?: number;
  details?: any;
  error?: string;
  lastChecked: Date;
}

export interface SystemHealthReport {
  overall: 'healthy' | 'unhealthy' | 'degraded';
  services: HealthCheckResult[];
  recommendations: string[];
  timestamp: Date;
}

export class DatabaseHealthChecker {
  private supabase: SupabaseClient;
  private pinecone: Pinecone;
  private neo4jDriver: Driver;
  private s3Client: S3Client;
  private jinaApiKey: string;

  constructor(config: {
    supabaseUrl: string;
    supabaseKey: string;
    pineconeApiKey: string;
    neo4jUri: string;
    neo4jUser: string;
    neo4jPassword: string;
    awsRegion?: string;
    jinaApiKey: string;
  }) {
    // Initialize Supabase
    this.supabase = createClient(config.supabaseUrl, config.supabaseKey);

    // Initialize Pinecone
    this.pinecone = new Pinecone({
      apiKey: config.pineconeApiKey,
    });

    // Initialize Neo4j
    this.neo4jDriver = neo4j.driver(
      config.neo4jUri,
      neo4j.auth.basic(config.neo4jUser, config.neo4jPassword)
    );

    // Initialize S3 (optional)
    if (config.awsRegion) {
      this.s3Client = new S3Client({ region: config.awsRegion });
    }

    this.jinaApiKey = config.jinaApiKey;
  }

  async checkSupabase(): Promise<HealthCheckResult> {
    const start = Date.now();
    const result: HealthCheckResult = {
      service: 'Supabase',
      status: 'healthy',
      lastChecked: new Date(),
    };

    try {
      // Check connection
      const { data, error } = await this.supabase
        .from('documents')
        .select('count', { count: 'exact', head: true });

      if (error) throw error;

      // Check all required tables exist
      const tables = ['documents', 'chunks', 'citations', 'processing_logs', 'etl_checkpoints'];
      const tableChecks = await Promise.all(
        tables.map(async (table) => {
          const { error } = await this.supabase
            .from(table)
            .select('id')
            .limit(1);
          return { table, exists: !error };
        })
      );

      const missingTables = tableChecks.filter(t => !t.exists).map(t => t.table);
      
      result.latency = Date.now() - start;
      result.details = {
        tablesChecked: tables.length,
        missingTables,
        documentCount: data || 0,
      };

      if (missingTables.length > 0) {
        result.status = 'unhealthy';
        result.error = `Missing tables: ${missingTables.join(', ')}`;
      }

    } catch (error) {
      result.status = 'unhealthy';
      result.error = error.message;
      result.latency = Date.now() - start;
    }

    return result;
  }

  async checkPinecone(): Promise<HealthCheckResult> {
    const start = Date.now();
    const result: HealthCheckResult = {
      service: 'Pinecone',
      status: 'healthy',
      lastChecked: new Date(),
    };

    try {
      // List indexes
      const indexes = await this.pinecone.listIndexes();
      
      // Check if nightingale index exists
      const nightingaleIndex = indexes.indexes?.find(idx => idx.name === 'nightingale');
      
      if (!nightingaleIndex) {
        result.status = 'unhealthy';
        result.error = 'Nightingale index not found';
      } else {
        // Get index stats
        const index = this.pinecone.index('nightingale');
        const stats = await index.describeIndexStats();
        
        result.details = {
          dimension: nightingaleIndex.dimension,
          metric: nightingaleIndex.metric,
          totalVectors: stats.totalRecordCount || 0,
          namespaces: stats.namespaces ? Object.keys(stats.namespaces).length : 0,
        };

        // Check dimensions match Jina embeddings
        if (nightingaleIndex.dimension !== 768) {
          result.status = 'unhealthy';
          result.error = `Index dimension ${nightingaleIndex.dimension} doesn't match Jina embedding dimension (768)`;
        }
      }

      result.latency = Date.now() - start;

    } catch (error) {
      result.status = 'unhealthy';
      result.error = error.message;
      result.latency = Date.now() - start;
    }

    return result;
  }

  async checkNeo4j(): Promise<HealthCheckResult> {
    const start = Date.now();
    const result: HealthCheckResult = {
      service: 'Neo4j',
      status: 'healthy',
      lastChecked: new Date(),
    };

    let session: Session | null = null;

    try {
      // Verify connectivity
      await this.neo4jDriver.verifyConnectivity();
      
      session = this.neo4jDriver.session();

      // Check indexes and constraints
      const indexResult = await session.run('SHOW INDEXES');
      const constraintResult = await session.run('SHOW CONSTRAINTS');
      
      // Count nodes and relationships
      const nodeCount = await session.run('MATCH (n) RETURN count(n) as count');
      const relCount = await session.run('MATCH ()-[r]->() RETURN count(r) as count');

      result.details = {
        indexes: indexResult.records.length,
        constraints: constraintResult.records.length,
        nodeCount: nodeCount.records[0].get('count').toNumber(),
        relationshipCount: relCount.records[0].get('count').toNumber(),
      };

      // Check required node labels exist
      const requiredLabels = ['Document', 'Entity', 'Threat', 'Vendor', 'Report'];
      const labelCheck = await session.run('CALL db.labels()');
      const existingLabels = labelCheck.records.map(r => r.get('label'));
      const missingLabels = requiredLabels.filter(l => !existingLabels.includes(l));

      if (missingLabels.length > 0) {
        result.status = 'degraded';
        result.details.missingLabels = missingLabels;
      }

      result.latency = Date.now() - start;

    } catch (error) {
      result.status = 'unhealthy';
      result.error = error.message;
      result.latency = Date.now() - start;
    } finally {
      if (session) await session.close();
    }

    return result;
  }

  async checkS3(): Promise<HealthCheckResult> {
    const start = Date.now();
    const result: HealthCheckResult = {
      service: 'AWS S3',
      status: 'healthy',
      lastChecked: new Date(),
    };

    if (!this.s3Client) {
      result.status = 'unhealthy';
      result.error = 'S3 client not configured';
      return result;
    }

    try {
      // Check bucket exists and is accessible
      const command = new HeadBucketCommand({ Bucket: 'project_aeon_dt' });
      await this.s3Client.send(command);
      
      result.latency = Date.now() - start;
      result.details = {
        bucket: 'project_aeon_dt',
        accessible: true,
      };

    } catch (error) {
      result.status = 'unhealthy';
      result.error = error.message;
      result.latency = Date.now() - start;
    }

    return result;
  }

  async checkJinaAI(): Promise<HealthCheckResult> {
    const start = Date.now();
    const result: HealthCheckResult = {
      service: 'Jina AI',
      status: 'healthy',
      lastChecked: new Date(),
    };

    try {
      // Test embedding endpoint
      const response = await axios.post(
        'https://api.jina.ai/v1/embeddings',
        {
          input: ['test'],
          model: 'jina-embeddings-v2-base-en',
        },
        {
          headers: {
            'Authorization': `Bearer ${this.jinaApiKey}`,
            'Content-Type': 'application/json',
          },
          timeout: 5000,
        }
      );

      if (response.data && response.data.data && response.data.data[0].embedding) {
        const embeddingDim = response.data.data[0].embedding.length;
        result.details = {
          model: 'jina-embeddings-v2-base-en',
          embeddingDimension: embeddingDim,
          responseTime: Date.now() - start,
        };

        if (embeddingDim !== 768) {
          result.status = 'unhealthy';
          result.error = `Embedding dimension ${embeddingDim} doesn't match expected 768`;
        }
      }

      result.latency = Date.now() - start;

    } catch (error) {
      result.status = 'unhealthy';
      result.error = error.response?.data?.error || error.message;
      result.latency = Date.now() - start;
    }

    return result;
  }

  async performFullHealthCheck(): Promise<SystemHealthReport> {
    logger.info('Starting comprehensive health check...');

    const checks = await Promise.all([
      this.checkSupabase(),
      this.checkPinecone(),
      this.checkNeo4j(),
      this.checkS3(),
      this.checkJinaAI(),
    ]);

    const unhealthyServices = checks.filter(c => c.status === 'unhealthy');
    const degradedServices = checks.filter(c => c.status === 'degraded');

    let overall: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
    if (unhealthyServices.length > 0) overall = 'unhealthy';
    else if (degradedServices.length > 0) overall = 'degraded';

    const recommendations: string[] = [];

    // Generate recommendations
    for (const check of checks) {
      if (check.status === 'unhealthy') {
        switch (check.service) {
          case 'Supabase':
            if (check.error?.includes('Missing tables')) {
              recommendations.push('Run database migrations: npm run setup-databases');
            }
            break;
          case 'Pinecone':
            if (check.error?.includes('not found')) {
              recommendations.push('Create Pinecone index: npm run create-pinecone-index');
            }
            if (check.error?.includes('dimension')) {
              recommendations.push('Recreate Pinecone index with 768 dimensions');
            }
            break;
          case 'Neo4j':
            recommendations.push('Check Neo4j connection settings and credentials');
            break;
          case 'AWS S3':
            recommendations.push('Configure AWS credentials or create S3 bucket');
            break;
          case 'Jina AI':
            recommendations.push('Verify Jina API key is valid');
            break;
        }
      }
    }

    const report: SystemHealthReport = {
      overall,
      services: checks,
      recommendations,
      timestamp: new Date(),
    };

    // Log results
    logger.info('Health check completed', {
      overall: report.overall,
      healthy: checks.filter(c => c.status === 'healthy').length,
      unhealthy: unhealthyServices.length,
      degraded: degradedServices.length,
    });

    return report;
  }

  async cleanup(): Promise<void> {
    await this.neo4jDriver.close();
  }

  // Helper method to display health report in CLI
  static displayReport(report: SystemHealthReport): void {
    console.log('\n' + '='.repeat(80));
    console.log('SYSTEM HEALTH REPORT');
    console.log('='.repeat(80));
    console.log(`Overall Status: ${report.overall.toUpperCase()}`);
    console.log(`Timestamp: ${report.timestamp.toISOString()}\n`);

    console.log('Service Status:');
    console.log('-'.repeat(80));
    
    for (const service of report.services) {
      const statusEmoji = {
        healthy: '🟢',
        unhealthy: '🔴',
        degraded: '🟡',
      }[service.status];
      
      console.log(`${statusEmoji} ${service.service.padEnd(15)} ${service.status.padEnd(10)} ${service.latency ? `(${service.latency}ms)` : ''}`);
      
      if (service.error) {
        console.log(`   ❌ Error: ${service.error}`);
      }
      
      if (service.details) {
        console.log(`   📊 Details: ${JSON.stringify(service.details, null, 2).split('\n').join('\n   ')}`);
      }
    }

    if (report.recommendations.length > 0) {
      console.log('\n📋 Recommendations:');
      console.log('-'.repeat(80));
      report.recommendations.forEach((rec, i) => {
        console.log(`${i + 1}. ${rec}`);
      });
    }

    console.log('\n' + '='.repeat(80) + '\n');
  }
}