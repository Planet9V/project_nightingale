import { SupabaseConnector } from '../connectors/SupabaseConnector';

export class SupabaseManager extends SupabaseConnector {
  constructor(config: any) {
    super(config);
  }

  // Additional manager methods
  async documentExists(documentId: string): Promise<boolean> {
    try {
      const data = await this.getDocument(documentId, {
        logger: console,
        metrics: { increment: () => {} }
      } as any);
      
      return data !== null;
    } catch (error) {
      return false;
    }
  }

  async storeDocument(document: any): Promise<any> {
    return this.insertDocument(document, {
      logger: console,
      metrics: { increment: () => {} }
    } as any);
  }

  async storeChunks(chunks: any[]): Promise<void> {
    for (const chunk of chunks) {
      await this.insertChunkMetadata(
        chunk.id,
        chunk.documentId,
        chunk.metadata,
        {
          logger: console,
          metrics: { increment: () => {} }
        } as any
      );
    }
  }
}