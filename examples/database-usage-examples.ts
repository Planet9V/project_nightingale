/**
 * Database Usage Examples for Project Nightingale
 * 
 * These examples show how to use the Supabase database service
 * for cybersecurity intelligence operations.
 */

import { db } from '../src/services/database';

// Example 1: Managing Prospects
async function prospectExamples() {
  // Create a new prospect
  const newProspect = await db.createProspect({
    account_id: 'A-150025',
    company_name: 'Pacific Energy Corporation',
    sector: 'Energy',
    criticality: 9,
    account_manager: 'Jim Vranicar',
    metadata: {
      region: 'West Coast',
      annual_revenue: '500M',
      employee_count: 2500
    }
  });

  // Get prospect by account ID
  const prospect = await db.getProspectByAccountId('A-150025');

  // List high-criticality energy prospects
  const energyProspects = await db.listProspects({
    sector: 'Energy',
    minCriticality: 8,
    status: 'active'
  });

  // Update prospect status
  await db.updateProspect(prospect.id, {
    status: 'engaged',
    metadata: {
      ...prospect.metadata,
      last_contact: new Date().toISOString()
    }
  });
}

// Example 2: Threat Intelligence Management
async function threatIntelligenceExamples() {
  // Create a new threat
  const threat = await db.createThreatIntelligence({
    threat_id: 'VOLT-TYPHOON-2025-001',
    threat_type: 'APT',
    threat_actor: 'Volt Typhoon',
    severity: 9,
    cve_ids: ['CVE-2025-1234', 'CVE-2025-5678'],
    description: 'Advanced persistent threat targeting critical infrastructure',
    mitigations: 'Apply security patches, implement network segmentation',
    first_seen: '2025-01-15T00:00:00Z',
    metadata: {
      targets: ['Energy', 'Water', 'Transportation'],
      ttps: ['T1190', 'T1133', 'T1021.001']
    }
  });

  // Get recent high-severity threats
  const recentThreats = await db.listThreats({
    minSeverity: 8,
    daysBack: 30,
    threatType: 'APT'
  });

  // Link threat to prospect
  await db.linkProspectToThreat(
    prospect.id,
    threat.id,
    0.85 // confidence score
  );
}

// Example 3: Vulnerability Tracking
async function vulnerabilityExamples() {
  // Create a vulnerability entry
  const vuln = await db.createVulnerability({
    cve_id: 'CVE-2025-1234',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    description: 'Critical RCE in industrial control system',
    affected_systems: ['Schneider Electric Modicon', 'Siemens S7-1200'],
    published_date: '2025-06-01',
    metadata: {
      exploit_available: true,
      patch_available: true,
      in_the_wild: true
    }
  });

  // Check if CVE exists
  const existingVuln = await db.getVulnerabilityByCVE('CVE-2025-1234');

  // List critical vulnerabilities from past week
  const criticalVulns = await db.listVulnerabilities({
    minCVSS: 9.0,
    daysBack: 7
  });
}

// Example 4: Campaign Artifacts
async function campaignArtifactExamples() {
  // Create an Express Attack Brief
  const eab = await db.createArtifact({
    prospect_id: prospect.id,
    artifact_type: 'express_attack_brief',
    title: 'Volt Typhoon Targeting Energy Sector Supply Chain',
    content: '# Executive Summary\n\n...',
    file_path: 'artifacts/eab/EAB-2025-001.md',
    status: 'published',
    metadata: {
      theme: 'supply_chain_attacks',
      severity: 'critical',
      distribution: 'executive'
    }
  });

  // Create an Executive Concierge Report
  const report = await db.createArtifact({
    prospect_id: prospect.id,
    artifact_type: 'executive_concierge_report',
    title: 'Pacific Energy Corporation Threat Intelligence Report',
    content: '# Threat Landscape Analysis\n\n...',
    status: 'draft',
    metadata: {
      generated_by: 'automated_system',
      version: '1.0'
    }
  });

  // List all artifacts for a prospect
  const artifacts = await db.listArtifactsForProspect(
    prospect.id,
    'express_attack_brief'
  );
}

// Example 5: Analytics and Reporting
async function analyticsExamples() {
  // Get threat summary for a prospect
  const threatSummary = await db.getProspectThreatSummary(prospect.id);
  console.log('Threat Summary:', threatSummary);

  // Get recent high-severity threats
  const highSeverityThreats = await db.getRecentHighSeverityThreats(7);
  console.log('High Severity Threats:', highSeverityThreats);

  // Track ETL pipeline execution
  const etlLog = await db.logETLRun('cisa_kev_import', 'CISA');
  
  // Update ETL log after completion
  await db.updateETLLog(etlLog.id, {
    status: 'completed',
    records_processed: 150,
    records_failed: 0,
    completed_at: new Date().toISOString()
  });
}

// Example 6: Vector Embedding Tracking (Pinecone Integration)
async function vectorEmbeddingExamples() {
  // Track that we've created embeddings for a prospect
  await db.trackVectorEmbedding(
    'prospect',
    prospect.id,
    `prospect_${prospect.id}_desc`,
    'text-embedding-3-large',
    1024
  );

  // Track threat intelligence embeddings
  await db.trackVectorEmbedding(
    'threat',
    threat.id,
    `threat_${threat.id}_desc`,
    'text-embedding-3-large',
    1024
  );
}

// Example 7: Health Checks
async function healthCheckExample() {
  const isHealthy = await db.checkDatabaseHealth();
  console.log('Database health:', isHealthy ? '✅ Healthy' : '❌ Unhealthy');
}

// Export examples for reference
export {
  prospectExamples,
  threatIntelligenceExamples,
  vulnerabilityExamples,
  campaignArtifactExamples,
  analyticsExamples,
  vectorEmbeddingExamples,
  healthCheckExample
};