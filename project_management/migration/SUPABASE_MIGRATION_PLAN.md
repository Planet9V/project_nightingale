# Supabase Database Migration Plan for Project Nightingale

**Created**: June 12, 2025  
**Purpose**: Migrate Project Nightingale to new Supabase database instance

---

## Current State Analysis

### Existing Infrastructure
1. **Database**: Currently using Prisma ORM (but no schema files found)
2. **Supabase**: Already has `supabase.ts` service configured
3. **Storage**: Vehicle images, user avatars, documents buckets
4. **Environment**: New Supabase credentials provided in `.env`

### New Supabase Instance
- **Project URL**: https://yopfdfezojpdnpgbolhu.supabase.co
- **Database**: PostgreSQL (blank, needs schema)
- **Storage Bucket**: nightingale
- **Region**: us-east-2

---

## Database Schema Design for Project Nightingale

Based on the project's cybersecurity intelligence focus, here's the proposed schema:

### Core Tables

```sql
-- Organizations/Prospects Table
CREATE TABLE prospects (
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
CREATE TABLE threat_intelligence (
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
CREATE TABLE vulnerabilities (
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
CREATE TABLE prospect_threats (
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
CREATE TABLE campaign_artifacts (
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
CREATE TABLE intelligence_sources (
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
CREATE TABLE etl_pipeline_logs (
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
CREATE TABLE vector_embeddings (
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

-- Create indexes for performance
CREATE INDEX idx_prospects_sector ON prospects(sector);
CREATE INDEX idx_prospects_criticality ON prospects(criticality);
CREATE INDEX idx_threats_type ON threat_intelligence(threat_type);
CREATE INDEX idx_threats_severity ON threat_intelligence(severity);
CREATE INDEX idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);
CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_prospect_threats_prospect ON prospect_threats(prospect_id);
CREATE INDEX idx_prospect_threats_threat ON prospect_threats(threat_id);
CREATE INDEX idx_artifacts_prospect ON campaign_artifacts(prospect_id);
CREATE INDEX idx_artifacts_type ON campaign_artifacts(artifact_type);
CREATE INDEX idx_embeddings_entity ON vector_embeddings(entity_type, entity_id);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to all tables
CREATE TRIGGER update_prospects_updated_at BEFORE UPDATE ON prospects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_threats_updated_at BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_prospect_threats_updated_at BEFORE UPDATE ON prospect_threats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_artifacts_updated_at BEFORE UPDATE ON campaign_artifacts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_sources_updated_at BEFORE UPDATE ON intelligence_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_embeddings_updated_at BEFORE UPDATE ON vector_embeddings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

---

## Row Level Security (RLS) Policies

```sql
-- Enable RLS on all tables
ALTER TABLE prospects ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE prospect_threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE intelligence_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE etl_pipeline_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vector_embeddings ENABLE ROW LEVEL SECURITY;

-- For now, allow service role full access (adjust based on auth requirements)
CREATE POLICY "Service role has full access to prospects" ON prospects
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to threats" ON threat_intelligence
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to vulnerabilities" ON vulnerabilities
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to prospect_threats" ON prospect_threats
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to artifacts" ON campaign_artifacts
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to sources" ON intelligence_sources
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to logs" ON etl_pipeline_logs
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
    
CREATE POLICY "Service role has full access to embeddings" ON vector_embeddings
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');
```

---

## Storage Bucket Configuration

```sql
-- Storage bucket already exists: nightingale
-- Configure storage policies for different artifact types

-- Create storage policies via Supabase dashboard or API:
-- 1. prospects/* - for prospect-related documents
-- 2. threats/* - for threat intelligence reports
-- 3. artifacts/* - for campaign artifacts
-- 4. exports/* - for generated reports
```

---

## Migration Steps

### 1. Database Schema Creation
Run the SQL schema in Supabase SQL Editor

### 2. Update Database Service
Create new database service to replace Prisma

### 3. Data Migration (if needed)
Export existing data and import to new Supabase instance

### 4. Update Application Code
- Replace Prisma client with Supabase client
- Update all database queries
- Update storage references

### 5. Testing
- Verify all CRUD operations
- Test storage functionality
- Validate data integrity

---

## Implementation Priority

1. **Immediate**: Create database schema
2. **High**: Update database service layer
3. **Medium**: Migrate existing data
4. **Low**: Optimize queries and add advanced features

This migration will provide Project Nightingale with a scalable, secure, and fully managed database solution integrated with storage capabilities.