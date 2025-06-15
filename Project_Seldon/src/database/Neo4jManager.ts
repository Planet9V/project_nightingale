import { Neo4jConnector } from '../connectors/Neo4jConnector';

export class Neo4jManager extends Neo4jConnector {
  constructor(config: any) {
    super(config);
  }

  // Additional manager methods
  async createDocument(document: any): Promise<any> {
    return this.upsertNode(
      {
        id: document.id,
        labels: ['Document'],
        properties: {
          title: document.title,
          source: document.source,
          createdAt: new Date().toISOString()
        }
      },
      {
        logger: console,
        metrics: { increment: () => {} }
      } as any
    );
  }

  async createEntity(entity: any): Promise<any> {
    return this.upsertNode(
      {
        id: entity.id,
        labels: ['Entity', entity.type],
        properties: entity
      },
      {
        logger: console,
        metrics: { increment: () => {} }
      } as any
    );
  }

  async createRelationship(relationship: any): Promise<any> {
    return this.upsertRelationship(
      {
        id: `${relationship.sourceId}-${relationship.type}-${relationship.targetId}`,
        type: relationship.type,
        startNodeId: relationship.sourceId,
        endNodeId: relationship.targetId,
        properties: relationship.properties || {}
      },
      {
        logger: console,
        metrics: { increment: () => {} }
      } as any
    );
  }

  async close(): Promise<void> {
    return this.cleanup();
  }
}