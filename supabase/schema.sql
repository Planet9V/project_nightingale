-- =====================================================
-- Project Nightingale Database Schema for Supabase
-- =====================================================
-- Created: June 12, 2025
-- Purpose: Complete database schema for cybersecurity intelligence platform
-- =====================================================

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================
-- CORE TABLES
-- =====================================================

-- Organizations/Prospects Table
CREATE TABLE IF NOT EXISTS prospects (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    account_id VARCHAR(50) UNIQUE NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    sector VARCHAR(100),
    criticality INTEGER CHECK (criticality >= 1 AND criticality <= 10),
    account_manager VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Threat Intelligence Table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    threat_id VARCHAR(100) UNIQUE NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    threat_actor VARCHAR(255),
    severity INTEGER CHECK (severity >= 1 AND severity <= 10),
    cve_ids TEXT[],
    description TEXT,
    mitigations TEXT,
    metadata JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    description TEXT,
    affected_systems TEXT[],
    published_date DATE,
    modified_date DATE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Prospect Threats Junction Table
CREATE TABLE IF NOT EXISTS prospect_threats (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    prospect_id UUID REFERENCES prospects(id) ON DELETE CASCADE,
    threat_id UUID REFERENCES threat_intelligence(id) ON DELETE CASCADE,
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'active',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(prospect_id, threat_id)
);

-- Campaign Artifacts Table
CREATE TABLE IF NOT EXISTS campaign_artifacts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    prospect_id UUID REFERENCES prospects(id) ON DELETE CASCADE,
    artifact_type VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    content TEXT,
    file_path VARCHAR(500),
    status VARCHAR(50) DEFAULT 'draft',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Intelligence Sources Table
CREATE TABLE IF NOT EXISTS intelligence_sources (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,
    url VARCHAR(500),
    api_endpoint VARCHAR(500),
    last_fetched TIMESTAMPTZ,
    fetch_frequency_hours INTEGER DEFAULT 24,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ETL Pipeline Logs Table
CREATE TABLE IF NOT EXISTS etl_pipeline_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    pipeline_name VARCHAR(255) NOT NULL,
    source_id UUID REFERENCES intelligence_sources(id),
    status VARCHAR(50) NOT NULL,
    records_processed INTEGER DEFAULT 0,
    records_failed INTEGER DEFAULT 0,
    error_details JSONB,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'
);

-- Vector Embeddings Table (for Pinecone sync)
CREATE TABLE IF NOT EXISTS vector_embeddings (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    entity_type VARCHAR(100) NOT NULL,
    entity_id UUID NOT NULL,
    vector_id VARCHAR(255) UNIQUE NOT NULL,
    embedding_model VARCHAR(100),
    dimensions INTEGER,
    last_synced TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Account Manager Playbooks Table
CREATE TABLE IF NOT EXISTS am_playbooks (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    account_manager VARCHAR(255) NOT NULL,
    playbook_version VARCHAR(20) DEFAULT 'v4.1',
    content TEXT,
    prospects TEXT[],
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Express Attack Briefs Table
CREATE TABLE IF NOT EXISTS express_attack_briefs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    brief_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    threat_actor VARCHAR(255),
    target_sector VARCHAR(100),
    attack_vector VARCHAR(255),
    content TEXT,
    severity INTEGER CHECK (severity >= 1 AND severity <= 10),
    metadata JSONB DEFAULT '{}',
    published_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- MCP Server Status Table
CREATE TABLE IF NOT EXISTS mcp_server_status (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    server_name VARCHAR(100) UNIQUE NOT NULL,
    server_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,
    configuration JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Prospects indexes
CREATE INDEX IF NOT EXISTS idx_prospects_sector ON prospects(sector);
CREATE INDEX IF NOT EXISTS idx_prospects_criticality ON prospects(criticality);
CREATE INDEX IF NOT EXISTS idx_prospects_account_manager ON prospects(account_manager);
CREATE INDEX IF NOT EXISTS idx_prospects_status ON prospects(status);

-- Threat intelligence indexes
CREATE INDEX IF NOT EXISTS idx_threats_type ON threat_intelligence(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_intelligence(severity);
CREATE INDEX IF NOT EXISTS idx_threats_actor ON threat_intelligence(threat_actor);
CREATE INDEX IF NOT EXISTS idx_threats_dates ON threat_intelligence(first_seen, last_seen);

-- Vulnerabilities indexes
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_dates ON vulnerabilities(published_date, modified_date);

-- Junction table indexes
CREATE INDEX IF NOT EXISTS idx_prospect_threats_prospect ON prospect_threats(prospect_id);
CREATE INDEX IF NOT EXISTS idx_prospect_threats_threat ON prospect_threats(threat_id);
CREATE INDEX IF NOT EXISTS idx_prospect_threats_confidence ON prospect_threats(confidence_score);

-- Artifacts indexes
CREATE INDEX IF NOT EXISTS idx_artifacts_prospect ON campaign_artifacts(prospect_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON campaign_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_status ON campaign_artifacts(status);

-- Vector embeddings indexes
CREATE INDEX IF NOT EXISTS idx_embeddings_entity ON vector_embeddings(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_embeddings_vector_id ON vector_embeddings(vector_id);

-- ETL logs indexes
CREATE INDEX IF NOT EXISTS idx_etl_logs_pipeline ON etl_pipeline_logs(pipeline_name);
CREATE INDEX IF NOT EXISTS idx_etl_logs_status ON etl_pipeline_logs(status);
CREATE INDEX IF NOT EXISTS idx_etl_logs_dates ON etl_pipeline_logs(started_at, completed_at);

-- =====================================================
-- TRIGGER FUNCTIONS
-- =====================================================

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- =====================================================
-- APPLY TRIGGERS TO ALL TABLES
-- =====================================================

-- Prospects
CREATE TRIGGER update_prospects_updated_at BEFORE UPDATE ON prospects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Threat Intelligence
CREATE TRIGGER update_threats_updated_at BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Vulnerabilities
CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Prospect Threats
CREATE TRIGGER update_prospect_threats_updated_at BEFORE UPDATE ON prospect_threats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Campaign Artifacts
CREATE TRIGGER update_artifacts_updated_at BEFORE UPDATE ON campaign_artifacts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Intelligence Sources
CREATE TRIGGER update_sources_updated_at BEFORE UPDATE ON intelligence_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Vector Embeddings
CREATE TRIGGER update_embeddings_updated_at BEFORE UPDATE ON vector_embeddings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- AM Playbooks
CREATE TRIGGER update_playbooks_updated_at BEFORE UPDATE ON am_playbooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Express Attack Briefs
CREATE TRIGGER update_briefs_updated_at BEFORE UPDATE ON express_attack_briefs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- MCP Server Status
CREATE TRIGGER update_mcp_status_updated_at BEFORE UPDATE ON mcp_server_status
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- ROW LEVEL SECURITY (RLS)
-- =====================================================

-- Enable RLS on all tables
ALTER TABLE prospects ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE prospect_threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE intelligence_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE etl_pipeline_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vector_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE am_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE express_attack_briefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_server_status ENABLE ROW LEVEL SECURITY;

-- =====================================================
-- RLS POLICIES
-- =====================================================

-- Service role has full access to all tables
CREATE POLICY "Service role full access - prospects" ON prospects
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - threats" ON threat_intelligence
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - vulnerabilities" ON vulnerabilities
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - prospect_threats" ON prospect_threats
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - artifacts" ON campaign_artifacts
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - sources" ON intelligence_sources
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - logs" ON etl_pipeline_logs
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - embeddings" ON vector_embeddings
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - playbooks" ON am_playbooks
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - briefs" ON express_attack_briefs
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role full access - mcp_status" ON mcp_server_status
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

-- Anon users can read public threat intelligence
CREATE POLICY "Anon read access - threats" ON threat_intelligence
    FOR SELECT USING (auth.jwt() ->> 'role' = 'anon');

CREATE POLICY "Anon read access - vulnerabilities" ON vulnerabilities
    FOR SELECT USING (auth.jwt() ->> 'role' = 'anon');

CREATE POLICY "Anon read access - briefs" ON express_attack_briefs
    FOR SELECT USING (auth.jwt() ->> 'role' = 'anon');

-- =====================================================
-- INITIAL DATA (Optional)
-- =====================================================

-- Insert default intelligence sources
INSERT INTO intelligence_sources (source_name, source_type, url, api_endpoint, is_active) VALUES
    ('CISA KEV', 'API', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', true),
    ('NVD', 'API', 'https://nvd.nist.gov/', 'https://services.nvd.nist.gov/rest/json/cves/2.0', true),
    ('MITRE ATT&CK', 'API', 'https://attack.mitre.org/', 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', true)
ON CONFLICT DO NOTHING;

-- Insert MCP server configurations
INSERT INTO mcp_server_status (server_name, server_type, status, configuration) VALUES
    ('pinecone', 'vector_db', 'unknown', '{"index": "nightingale", "dimensions": 1024}'::jsonb),
    ('neo4j', 'graph_db', 'unknown', '{"database": "neo4j"}'::jsonb),
    ('graphlit', 'content_mgmt', 'unknown', '{"environment_id": "3fbe0e93-733b-461b-a950-7f87d3d85d05"}'::jsonb),
    ('taskmaster', 'task_mgmt', 'unknown', '{"api_keys_configured": true}'::jsonb),
    ('tavily', 'web_search', 'unknown', '{"api_key_configured": true}'::jsonb),
    ('context7', 'documentation', 'unknown', '{}'::jsonb),
    ('jina-ai', 'ai_search', 'unknown', '{}'::jsonb),
    ('sequential-thinking', 'analysis', 'unknown', '{}'::jsonb),
    ('antv-charts', 'visualization', 'unknown', '{}'::jsonb)
ON CONFLICT DO NOTHING;

-- =====================================================
-- FUNCTIONS FOR COMMON OPERATIONS
-- =====================================================

-- Function to get prospect threat summary
CREATE OR REPLACE FUNCTION get_prospect_threat_summary(p_prospect_id UUID)
RETURNS TABLE (
    threat_type VARCHAR,
    threat_count INTEGER,
    avg_severity NUMERIC,
    max_severity INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ti.threat_type,
        COUNT(*)::INTEGER as threat_count,
        AVG(ti.severity)::NUMERIC(3,1) as avg_severity,
        MAX(ti.severity) as max_severity
    FROM prospect_threats pt
    JOIN threat_intelligence ti ON pt.threat_id = ti.id
    WHERE pt.prospect_id = p_prospect_id
    AND pt.status = 'active'
    GROUP BY ti.threat_type
    ORDER BY max_severity DESC, threat_count DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get recent high-severity threats
CREATE OR REPLACE FUNCTION get_recent_high_severity_threats(p_days INTEGER DEFAULT 7)
RETURNS TABLE (
    threat_id VARCHAR,
    threat_type VARCHAR,
    threat_actor VARCHAR,
    severity INTEGER,
    first_seen TIMESTAMPTZ,
    affected_prospect_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ti.threat_id,
        ti.threat_type,
        ti.threat_actor,
        ti.severity,
        ti.first_seen,
        COUNT(DISTINCT pt.prospect_id)::INTEGER as affected_prospect_count
    FROM threat_intelligence ti
    LEFT JOIN prospect_threats pt ON ti.id = pt.threat_id
    WHERE ti.severity >= 8
    AND ti.first_seen >= NOW() - INTERVAL '1 day' * p_days
    GROUP BY ti.id, ti.threat_id, ti.threat_type, ti.threat_actor, ti.severity, ti.first_seen
    ORDER BY ti.first_seen DESC, ti.severity DESC;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- VIEWS FOR COMMON QUERIES
-- =====================================================

-- View for active high-criticality prospects with threats
CREATE OR REPLACE VIEW high_risk_prospects AS
SELECT 
    p.id,
    p.account_id,
    p.company_name,
    p.sector,
    p.criticality,
    p.account_manager,
    COUNT(DISTINCT pt.threat_id) as active_threat_count,
    MAX(ti.severity) as max_threat_severity,
    AVG(ti.severity)::NUMERIC(3,1) as avg_threat_severity
FROM prospects p
LEFT JOIN prospect_threats pt ON p.id = pt.prospect_id AND pt.status = 'active'
LEFT JOIN threat_intelligence ti ON pt.threat_id = ti.id
WHERE p.status = 'active'
AND p.criticality >= 8
GROUP BY p.id, p.account_id, p.company_name, p.sector, p.criticality, p.account_manager
ORDER BY p.criticality DESC, max_threat_severity DESC NULLS LAST;

-- View for recent campaign artifacts
CREATE OR REPLACE VIEW recent_campaign_artifacts AS
SELECT 
    ca.id,
    ca.artifact_type,
    ca.title,
    ca.status,
    ca.created_at,
    p.account_id,
    p.company_name,
    p.account_manager
FROM campaign_artifacts ca
JOIN prospects p ON ca.prospect_id = p.id
WHERE ca.created_at >= NOW() - INTERVAL '30 days'
ORDER BY ca.created_at DESC;

-- =====================================================
-- GRANT PERMISSIONS (if needed for additional roles)
-- =====================================================

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- Grant select on specific tables to anon role
GRANT SELECT ON threat_intelligence, vulnerabilities, express_attack_briefs TO anon;

-- Grant all on tables to authenticated role
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;

-- Grant usage on sequences to authenticated
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- =====================================================
-- COMPLETION MESSAGE
-- =====================================================

-- Schema creation completed successfully!
-- Next steps:
-- 1. Configure storage buckets in Supabase dashboard
-- 2. Update application code to use Supabase client
-- 3. Import any existing data
-- 4. Test all CRUD operations