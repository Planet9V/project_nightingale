/**
 * Neo4j Graph Database Connector for Project Seldon
 * Handles entity relationships and graph operations
 */

import neo4j, { Driver, Session, ManagedTransaction } from 'neo4j-driver';
import { logger } from '../utils/logger';
import { Configuration } from '../config/types';
import { ETLContext } from '../types/index';

export interface Neo4jNode {
  id: string;
  labels: string[];
  properties: Record<string, any>;
}

export interface Neo4jRelationship {
  id: string;
  type: string;
  startNodeId: string;
  endNodeId: string;
  properties: Record<string, any>;
}

export interface GraphQueryResult {
  nodes: Neo4jNode[];
  relationships: Neo4jRelationship[];
  metadata: Record<string, any>;
}

export interface GraphStats {
  nodeCount: number;
  relationshipCount: number;
  nodeTypes: Record<string, number>;
  relationshipTypes: Record<string, number>;
}

export class Neo4jConnector {
  private driver: Driver;
  private config: Configuration;
  private isConnected: boolean = false;

  constructor(config: Configuration) {
    this.config = config;
    this.driver = neo4j.driver(
      config.databases.neo4j.uri,
      neo4j.auth.basic(
        config.databases.neo4j.username,
        config.databases.neo4j.password
      ),
      {
        maxConnectionPoolSize: config.databases.neo4j.maxConnectionPoolSize,
        connectionTimeout: config.databases.neo4j.connectionTimeout,
        disableLosslessIntegers: true,
      }
    );
  }

  /**
   * Test database connection
   */
  public async testConnection(): Promise<boolean> {
    let session: Session | null = null;
    
    try {
      logger.info('Testing Neo4j connection');
      
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });
      
      await session.run('RETURN 1 as result');
      
      this.isConnected = true;
      logger.info('Neo4j connection successful');
      return true;
    } catch (error) {
      logger.error('Neo4j connection test failed', error as Error);
      return false;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Create or update a node
   */
  public async upsertNode(
    node: Neo4jNode,
    context: ETLContext
  ): Promise<Neo4jNode> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const labels = node.labels.join(':');
      const query = `
        MERGE (n:${labels} {id: $id})
        SET n += $properties
        SET n.updatedAt = datetime()
        RETURN n
      `;

      const result = await session.run(query, {
        id: node.id,
        properties: {
          ...node.properties,
          createdAt: node.properties.createdAt || new Date().toISOString(),
        },
      });

      context.metrics.increment('neo4j.nodes.upserted', 1, {
        labels: node.labels.join(','),
      });

      const record = result.records[0];
      return this.parseNode(record.get('n'));
    } catch (error) {
      context.logger.error('Failed to upsert node', error as Error, {
        nodeId: node.id,
        labels: node.labels,
      });
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Create multiple nodes in batch
   */
  public async upsertNodesBatch(
    nodes: Neo4jNode[],
    context: ETLContext
  ): Promise<Neo4jNode[]> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const results: Neo4jNode[] = [];
      
      await session.executeWrite(async (tx: ManagedTransaction) => {
        for (const node of nodes) {
          const labels = node.labels.join(':');
          const query = `
            MERGE (n:${labels} {id: $id})
            SET n += $properties
            SET n.updatedAt = datetime()
            RETURN n
          `;

          const result = await tx.run(query, {
            id: node.id,
            properties: {
              ...node.properties,
              createdAt: node.properties.createdAt || new Date().toISOString(),
            },
          });

          const record = result.records[0];
          results.push(this.parseNode(record.get('n')));
        }
      });

      context.metrics.increment('neo4j.nodes.upserted', nodes.length);
      
      return results;
    } catch (error) {
      context.logger.error('Failed to upsert nodes batch', error as Error);
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Create or update a relationship
   */
  public async upsertRelationship(
    relationship: Neo4jRelationship,
    context: ETLContext
  ): Promise<Neo4jRelationship> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const query = `
        MATCH (a {id: $startNodeId})
        MATCH (b {id: $endNodeId})
        MERGE (a)-[r:${relationship.type}]->(b)
        SET r += $properties
        SET r.id = $id
        SET r.updatedAt = datetime()
        RETURN r, id(a) as startId, id(b) as endId
      `;

      const result = await session.run(query, {
        id: relationship.id,
        startNodeId: relationship.startNodeId,
        endNodeId: relationship.endNodeId,
        properties: {
          ...relationship.properties,
          createdAt: relationship.properties.createdAt || new Date().toISOString(),
        },
      });

      context.metrics.increment('neo4j.relationships.upserted', 1, {
        type: relationship.type,
      });

      const record = result.records[0];
      return this.parseRelationship(record.get('r'), record.get('startId'), record.get('endId'));
    } catch (error) {
      context.logger.error('Failed to upsert relationship', error as Error, {
        relationshipId: relationship.id,
        type: relationship.type,
      });
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Query nodes by properties
   */
  public async queryNodes(
    labels: string[],
    properties: Record<string, any>,
    limit: number = 100,
    context: ETLContext
  ): Promise<Neo4jNode[]> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const labelString = labels.length > 0 ? `:${labels.join(':')}` : '';
      const whereClause = Object.keys(properties).length > 0
        ? 'WHERE ' + Object.keys(properties).map(key => `n.${key} = $${key}`).join(' AND ')
        : '';

      const query = `
        MATCH (n${labelString})
        ${whereClause}
        RETURN n
        LIMIT $limit
      `;

      const result = await session.run(query, {
        ...properties,
        limit: neo4j.int(limit),
      });

      return result.records.map(record => this.parseNode(record.get('n')));
    } catch (error) {
      context.logger.error('Failed to query nodes', error as Error);
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Find paths between nodes
   */
  public async findPaths(
    startNodeId: string,
    endNodeId: string,
    maxDepth: number = 5,
    context: ETLContext
  ): Promise<GraphQueryResult[]> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const query = `
        MATCH path = (start {id: $startId})-[*..${maxDepth}]-(end {id: $endId})
        RETURN path
        LIMIT 10
      `;

      const result = await session.run(query, {
        startId: startNodeId,
        endId: endNodeId,
      });

      const paths: GraphQueryResult[] = [];
      
      for (const record of result.records) {
        const path = record.get('path');
        const nodes: Neo4jNode[] = [];
        const relationships: Neo4jRelationship[] = [];

        // Extract nodes
        for (const node of path.nodes) {
          nodes.push(this.parseNode(node));
        }

        // Extract relationships
        for (const rel of path.relationships) {
          relationships.push(this.parseRelationship(rel, rel.start, rel.end));
        }

        paths.push({
          nodes,
          relationships,
          metadata: {
            length: path.length,
          },
        });
      }

      return paths;
    } catch (error) {
      context.logger.error('Failed to find paths', error as Error, {
        startNodeId,
        endNodeId,
      });
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Get node neighbors
   */
  public async getNeighbors(
    nodeId: string,
    relationshipTypes: string[] = [],
    direction: 'in' | 'out' | 'both' = 'both',
    limit: number = 50,
    context: ETLContext
  ): Promise<GraphQueryResult> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const relTypeClause = relationshipTypes.length > 0
        ? `:${relationshipTypes.join('|')}`
        : '';
      
      const directionArrow = direction === 'in' ? '<-' : direction === 'out' ? '->' : '-';

      const query = `
        MATCH (n {id: $nodeId})${directionArrow}[r${relTypeClause}]${directionArrow}(neighbor)
        RETURN n, r, neighbor
        LIMIT $limit
      `;

      const result = await session.run(query, {
        nodeId,
        limit: neo4j.int(limit),
      });

      const nodes: Neo4jNode[] = [];
      const relationships: Neo4jRelationship[] = [];
      const nodeSet = new Set<string>();

      for (const record of result.records) {
        const sourceNode = this.parseNode(record.get('n'));
        const targetNode = this.parseNode(record.get('neighbor'));
        const relationship = this.parseRelationship(
          record.get('r'),
          sourceNode.id,
          targetNode.id
        );

        if (!nodeSet.has(sourceNode.id)) {
          nodes.push(sourceNode);
          nodeSet.add(sourceNode.id);
        }
        
        if (!nodeSet.has(targetNode.id)) {
          nodes.push(targetNode);
          nodeSet.add(targetNode.id);
        }

        relationships.push(relationship);
      }

      return {
        nodes,
        relationships,
        metadata: {
          centerNodeId: nodeId,
          direction,
        },
      };
    } catch (error) {
      context.logger.error('Failed to get neighbors', error as Error, {
        nodeId,
      });
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Delete node and its relationships
   */
  public async deleteNode(
    nodeId: string,
    context: ETLContext
  ): Promise<boolean> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const query = `
        MATCH (n {id: $nodeId})
        DETACH DELETE n
        RETURN count(n) as deletedCount
      `;

      const result = await session.run(query, { nodeId });
      const deletedCount = result.records[0].get('deletedCount').toNumber();

      context.metrics.increment('neo4j.nodes.deleted', deletedCount);
      
      return deletedCount > 0;
    } catch (error) {
      context.logger.error('Failed to delete node', error as Error, {
        nodeId,
      });
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Execute custom Cypher query
   */
  public async executeCypher<T = any>(
    query: string,
    parameters: Record<string, any> = {},
    context: ETLContext
  ): Promise<T[]> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const result = await session.run(query, parameters);
      
      return result.records.map(record => record.toObject() as T);
    } catch (error) {
      context.logger.error('Failed to execute Cypher query', error as Error, {
        query,
      });
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Get database statistics
   */
  public async getStatistics(context: ETLContext): Promise<GraphStats> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      // Get node counts by label
      const nodeCountQuery = `
        CALL db.labels() YIELD label
        CALL apoc.cypher.run('MATCH (n:' + label + ') RETURN count(n) as count', {})
        YIELD value
        RETURN label, value.count as count
      `;

      // Get relationship counts by type
      const relCountQuery = `
        CALL db.relationshipTypes() YIELD relationshipType
        CALL apoc.cypher.run('MATCH ()-[r:' + relationshipType + ']->() RETURN count(r) as count', {})
        YIELD value
        RETURN relationshipType, value.count as count
      `;

      // Get total counts
      const totalQuery = `
        MATCH (n)
        WITH count(n) as nodeCount
        MATCH ()-[r]->()
        RETURN nodeCount, count(r) as relationshipCount
      `;

      const [nodeResults, relResults, totalResults] = await Promise.all([
        session.run(nodeCountQuery).catch(() => ({ records: [] })),
        session.run(relCountQuery).catch(() => ({ records: [] })),
        session.run(totalQuery),
      ]);

      const nodeTypes: Record<string, number> = {};
      for (const record of nodeResults.records) {
        nodeTypes[record.get('label')] = record.get('count').toNumber();
      }

      const relationshipTypes: Record<string, number> = {};
      for (const record of relResults.records) {
        relationshipTypes[record.get('relationshipType')] = record.get('count').toNumber();
      }

      const totalRecord = totalResults.records[0];
      
      return {
        nodeCount: totalRecord.get('nodeCount').toNumber(),
        relationshipCount: totalRecord.get('relationshipCount').toNumber(),
        nodeTypes,
        relationshipTypes,
      };
    } catch (error) {
      context.logger.error('Failed to get Neo4j statistics', error as Error);
      
      // Return empty stats on error
      return {
        nodeCount: 0,
        relationshipCount: 0,
        nodeTypes: {},
        relationshipTypes: {},
      };
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Create indexes for better performance
   */
  public async createIndexes(context: ETLContext): Promise<void> {
    let session: Session | null = null;
    
    try {
      session = this.driver.session({
        database: this.config.databases.neo4j.database,
      });

      const indexes = [
        'CREATE INDEX IF NOT EXISTS FOR (n:Document) ON (n.id)',
        'CREATE INDEX IF NOT EXISTS FOR (n:Prospect) ON (n.id)',
        'CREATE INDEX IF NOT EXISTS FOR (n:Threat) ON (n.id)',
        'CREATE INDEX IF NOT EXISTS FOR (n:Entity) ON (n.name)',
        'CREATE INDEX IF NOT EXISTS FOR (n:Tag) ON (n.name)',
      ];

      for (const index of indexes) {
        await session.run(index);
      }

      context.logger.info('Neo4j indexes created successfully');
    } catch (error) {
      context.logger.error('Failed to create indexes', error as Error);
      throw error;
    } finally {
      if (session) {
        await session.close();
      }
    }
  }

  /**
   * Parse Neo4j node to our format
   */
  private parseNode(node: any): Neo4jNode {
    return {
      id: node.properties.id || node.identity.toString(),
      labels: node.labels,
      properties: node.properties,
    };
  }

  /**
   * Parse Neo4j relationship to our format
   */
  private parseRelationship(rel: any, startId: string, endId: string): Neo4jRelationship {
    return {
      id: rel.properties.id || rel.identity.toString(),
      type: rel.type,
      startNodeId: startId,
      endNodeId: endId,
      properties: rel.properties,
    };
  }

  /**
   * Cleanup and close connections
   */
  public async cleanup(): Promise<void> {
    logger.info('Cleaning up Neo4j connector');
    await this.driver.close();
    this.isConnected = false;
  }

  /**
   * Get connection status
   */
  public getConnectionStatus(): boolean {
    return this.isConnected;
  }
}