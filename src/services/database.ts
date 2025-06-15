import { supabaseAdmin } from './supabase';
import { logger } from '../utils/logger';

// Type definitions for Project Nightingale entities
export interface Prospect {
  id?: string;
  account_id: string;
  company_name: string;
  sector?: string;
  criticality?: number;
  account_manager?: string;
  status?: string;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

export interface ThreatIntelligence {
  id?: string;
  threat_id: string;
  threat_type: string;
  threat_actor?: string;
  severity?: number;
  cve_ids?: string[];
  description?: string;
  mitigations?: string;
  metadata?: Record<string, any>;
  first_seen?: string;
  last_seen?: string;
  created_at?: string;
  updated_at?: string;
}

export interface Vulnerability {
  id?: string;
  cve_id: string;
  cvss_score?: number;
  cvss_vector?: string;
  description?: string;
  affected_systems?: string[];
  published_date?: string;
  modified_date?: string;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

export interface CampaignArtifact {
  id?: string;
  prospect_id: string;
  artifact_type: string;
  title: string;
  content?: string;
  file_path?: string;
  status?: string;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

// Database service class
export class DatabaseService {
  // Prospects operations
  async createProspect(prospect: Prospect) {
    try {
      const { data, error } = await supabaseAdmin
        .from('prospects')
        .insert(prospect)
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Created prospect: ${data.company_name} (${data.account_id})`);
      return data;
    } catch (error) {
      logger.error('Failed to create prospect:', error);
      throw error;
    }
  }

  async getProspect(id: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('prospects')
        .select('*')
        .eq('id', id)
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to get prospect ${id}:`, error);
      throw error;
    }
  }

  async getProspectByAccountId(accountId: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('prospects')
        .select('*')
        .eq('account_id', accountId)
        .single();

      if (error && error.code !== 'PGRST116') throw error; // PGRST116 = not found
      return data;
    } catch (error) {
      logger.error(`Failed to get prospect by account ID ${accountId}:`, error);
      throw error;
    }
  }

  async listProspects(filters?: {
    sector?: string;
    minCriticality?: number;
    accountManager?: string;
    status?: string;
  }) {
    try {
      let query = supabaseAdmin.from('prospects').select('*');

      if (filters?.sector) {
        query = query.eq('sector', filters.sector);
      }
      if (filters?.minCriticality) {
        query = query.gte('criticality', filters.minCriticality);
      }
      if (filters?.accountManager) {
        query = query.eq('account_manager', filters.accountManager);
      }
      if (filters?.status) {
        query = query.eq('status', filters.status);
      }

      const { data, error } = await query.order('criticality', { ascending: false });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error('Failed to list prospects:', error);
      throw error;
    }
  }

  async updateProspect(id: string, updates: Partial<Prospect>) {
    try {
      const { data, error } = await supabaseAdmin
        .from('prospects')
        .update(updates)
        .eq('id', id)
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Updated prospect: ${data.company_name} (${data.account_id})`);
      return data;
    } catch (error) {
      logger.error(`Failed to update prospect ${id}:`, error);
      throw error;
    }
  }

  // Threat Intelligence operations
  async createThreatIntelligence(threat: ThreatIntelligence) {
    try {
      const { data, error } = await supabaseAdmin
        .from('threat_intelligence')
        .insert(threat)
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Created threat intelligence: ${data.threat_id}`);
      return data;
    } catch (error) {
      logger.error('Failed to create threat intelligence:', error);
      throw error;
    }
  }

  async getThreatIntelligence(id: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('threat_intelligence')
        .select('*')
        .eq('id', id)
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to get threat intelligence ${id}:`, error);
      throw error;
    }
  }

  async listThreats(filters?: {
    threatType?: string;
    minSeverity?: number;
    threatActor?: string;
    daysBack?: number;
  }) {
    try {
      let query = supabaseAdmin.from('threat_intelligence').select('*');

      if (filters?.threatType) {
        query = query.eq('threat_type', filters.threatType);
      }
      if (filters?.minSeverity) {
        query = query.gte('severity', filters.minSeverity);
      }
      if (filters?.threatActor) {
        query = query.eq('threat_actor', filters.threatActor);
      }
      if (filters?.daysBack) {
        const dateThreshold = new Date();
        dateThreshold.setDate(dateThreshold.getDate() - filters.daysBack);
        query = query.gte('first_seen', dateThreshold.toISOString());
      }

      const { data, error } = await query.order('severity', { ascending: false });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error('Failed to list threats:', error);
      throw error;
    }
  }

  // Vulnerability operations
  async createVulnerability(vulnerability: Vulnerability) {
    try {
      const { data, error } = await supabaseAdmin
        .from('vulnerabilities')
        .insert(vulnerability)
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Created vulnerability: ${data.cve_id}`);
      return data;
    } catch (error) {
      logger.error('Failed to create vulnerability:', error);
      throw error;
    }
  }

  async getVulnerabilityByCVE(cveId: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('vulnerabilities')
        .select('*')
        .eq('cve_id', cveId)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to get vulnerability ${cveId}:`, error);
      throw error;
    }
  }

  async listVulnerabilities(filters?: {
    minCVSS?: number;
    affectedSystem?: string;
    daysBack?: number;
  }) {
    try {
      let query = supabaseAdmin.from('vulnerabilities').select('*');

      if (filters?.minCVSS) {
        query = query.gte('cvss_score', filters.minCVSS);
      }
      if (filters?.affectedSystem) {
        query = query.contains('affected_systems', [filters.affectedSystem]);
      }
      if (filters?.daysBack) {
        const dateThreshold = new Date();
        dateThreshold.setDate(dateThreshold.getDate() - filters.daysBack);
        query = query.gte('published_date', dateThreshold.toISOString());
      }

      const { data, error } = await query.order('cvss_score', { ascending: false });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error('Failed to list vulnerabilities:', error);
      throw error;
    }
  }

  // Prospect-Threat associations
  async linkProspectToThreat(prospectId: string, threatId: string, confidenceScore: number = 0.5) {
    try {
      const { data, error } = await supabaseAdmin
        .from('prospect_threats')
        .insert({
          prospect_id: prospectId,
          threat_id: threatId,
          confidence_score: confidenceScore,
          status: 'active'
        })
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Linked prospect ${prospectId} to threat ${threatId}`);
      return data;
    } catch (error) {
      logger.error('Failed to link prospect to threat:', error);
      throw error;
    }
  }

  async getProspectThreats(prospectId: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('prospect_threats')
        .select(`
          *,
          threat:threat_intelligence(*)
        `)
        .eq('prospect_id', prospectId)
        .eq('status', 'active')
        .order('confidence_score', { ascending: false });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to get threats for prospect ${prospectId}:`, error);
      throw error;
    }
  }

  // Campaign Artifacts operations
  async createArtifact(artifact: CampaignArtifact) {
    try {
      const { data, error } = await supabaseAdmin
        .from('campaign_artifacts')
        .insert(artifact)
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Created artifact: ${data.title}`);
      return data;
    } catch (error) {
      logger.error('Failed to create artifact:', error);
      throw error;
    }
  }

  async getArtifact(id: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('campaign_artifacts')
        .select(`
          *,
          prospect:prospects(*)
        `)
        .eq('id', id)
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to get artifact ${id}:`, error);
      throw error;
    }
  }

  async listArtifactsForProspect(prospectId: string, artifactType?: string) {
    try {
      let query = supabaseAdmin
        .from('campaign_artifacts')
        .select('*')
        .eq('prospect_id', prospectId);

      if (artifactType) {
        query = query.eq('artifact_type', artifactType);
      }

      const { data, error } = await query.order('created_at', { ascending: false });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to list artifacts for prospect ${prospectId}:`, error);
      throw error;
    }
  }

  // ETL Pipeline logging
  async logETLRun(pipelineName: string, sourceId?: string) {
    try {
      const { data, error } = await supabaseAdmin
        .from('etl_pipeline_logs')
        .insert({
          pipeline_name: pipelineName,
          source_id: sourceId,
          status: 'running',
          started_at: new Date().toISOString()
        })
        .select()
        .single();

      if (error) throw error;
      
      logger.info(`Started ETL pipeline: ${pipelineName}`);
      return data;
    } catch (error) {
      logger.error('Failed to log ETL run:', error);
      throw error;
    }
  }

  async updateETLLog(
    logId: string, 
    updates: {
      status?: string;
      records_processed?: number;
      records_failed?: number;
      error_details?: any;
      completed_at?: string;
    }
  ) {
    try {
      const { data, error } = await supabaseAdmin
        .from('etl_pipeline_logs')
        .update(updates)
        .eq('id', logId)
        .select()
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to update ETL log ${logId}:`, error);
      throw error;
    }
  }

  // Vector embeddings tracking
  async trackVectorEmbedding(
    entityType: string,
    entityId: string,
    vectorId: string,
    embeddingModel: string = 'text-embedding-3-large',
    dimensions: number = 1024
  ) {
    try {
      const { data, error } = await supabaseAdmin
        .from('vector_embeddings')
        .upsert({
          entity_type: entityType,
          entity_id: entityId,
          vector_id: vectorId,
          embedding_model: embeddingModel,
          dimensions: dimensions,
          last_synced: new Date().toISOString()
        })
        .select()
        .single();

      if (error) throw error;
      
      logger.debug(`Tracked vector embedding for ${entityType} ${entityId}`);
      return data;
    } catch (error) {
      logger.error('Failed to track vector embedding:', error);
      throw error;
    }
  }

  // Health check
  async checkDatabaseHealth(): Promise<boolean> {
    try {
      const start = Date.now();
      const { error } = await supabaseAdmin
        .from('prospects')
        .select('count')
        .single();
      
      const duration = Date.now() - start;
      
      if (error && error.code !== 'PGRST116') {
        throw error;
      }
      
      logger.debug(`Database health check completed in ${duration}ms`);
      return true;
    } catch (error) {
      logger.error('Database health check failed:', error);
      return false;
    }
  }

  // Utility functions
  async getProspectThreatSummary(prospectId: string) {
    try {
      const { data, error } = await supabaseAdmin
        .rpc('get_prospect_threat_summary', { p_prospect_id: prospectId });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error(`Failed to get threat summary for prospect ${prospectId}:`, error);
      throw error;
    }
  }

  async getRecentHighSeverityThreats(daysBack: number = 7) {
    try {
      const { data, error } = await supabaseAdmin
        .rpc('get_recent_high_severity_threats', { p_days: daysBack });

      if (error) throw error;
      return data;
    } catch (error) {
      logger.error('Failed to get recent high severity threats:', error);
      throw error;
    }
  }
}

// Export singleton instance
export const db = new DatabaseService();

// Initialize database connection test
db.checkDatabaseHealth().then((healthy) => {
  if (healthy) {
    logger.info('✅ Supabase database connection successful');
  } else {
    logger.error('❌ Supabase database connection failed');
  }
}).catch((error) => {
  logger.error('Failed to check database health:', error);
});