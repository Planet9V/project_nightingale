-- Project Seldon ETL Pipeline Database Schema
-- Complete Supabase PostgreSQL Schema with Vector Support

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS citations CASCADE;
DROP TABLE IF EXISTS chunks CASCADE;
DROP TABLE IF EXISTS processing_logs CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS etl_checkpoints CASCADE;
DROP TABLE IF EXISTS api_usage_metrics CASCADE;

-- Documents table - stores original document metadata
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    content TEXT, -- Full document content for reference
    source_path TEXT NOT NULL,
    s3_bucket TEXT,
    s3_key TEXT,
    file_type VARCHAR(50) NOT NULL,
    file_size BIGINT NOT NULL,
    hash VARCHAR(64) NOT NULL UNIQUE, -- SHA256 hash for deduplication
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_file_size CHECK (file_size > 0)
);

-- Chunks table - stores document chunks with embeddings
CREATE TABLE chunks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    start_char INTEGER NOT NULL,
    end_char INTEGER NOT NULL,
    embedding vector(768), -- Jina embeddings dimension
    metadata JSONB DEFAULT '{}',
    tokens INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT valid_char_positions CHECK (start_char >= 0 AND end_char > start_char),
    CONSTRAINT unique_chunk_per_doc UNIQUE (document_id, chunk_index)
);

-- Citations table - stores exact quotes with positions
CREATE TABLE citations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chunk_id UUID NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
    quote TEXT NOT NULL,
    start_position INTEGER NOT NULL,
    end_position INTEGER NOT NULL,
    context TEXT, -- Surrounding text for context
    confidence FLOAT DEFAULT 1.0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT valid_positions CHECK (start_position >= 0 AND end_position > start_position),
    CONSTRAINT valid_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

-- Processing logs table - tracks ETL pipeline execution
CREATE TABLE processing_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    batch_id UUID,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    stage VARCHAR(100),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,
    error TEXT,
    error_stack TEXT,
    retry_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    CONSTRAINT valid_status CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'skipped'))
);

-- ETL checkpoints table - for resume capability
CREATE TABLE etl_checkpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    batch_id UUID NOT NULL,
    checkpoint_type VARCHAR(50) NOT NULL,
    checkpoint_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_checkpoint_type CHECK (checkpoint_type IN ('batch', 'document', 'chunk', 'embedding', 'final'))
);

-- API usage metrics table - track Jina AI usage
CREATE TABLE api_usage_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service VARCHAR(50) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    tokens_used INTEGER,
    cost_usd DECIMAL(10, 6),
    response_time_ms INTEGER,
    status_code INTEGER,
    error TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT valid_service CHECK (service IN ('jina', 'openai', 'anthropic', 'other'))
);

-- Create indexes for performance
CREATE INDEX idx_documents_hash ON documents(hash);
CREATE INDEX idx_documents_source_path ON documents(source_path);
CREATE INDEX idx_documents_file_type ON documents(file_type);
CREATE INDEX idx_documents_created_at ON documents(created_at DESC);
CREATE INDEX idx_documents_metadata ON documents USING GIN(metadata);

CREATE INDEX idx_chunks_document_id ON chunks(document_id);
CREATE INDEX idx_chunks_metadata ON chunks USING GIN(metadata);
-- Vector similarity search index
CREATE INDEX idx_chunks_embedding ON chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE INDEX idx_citations_chunk_id ON citations(chunk_id);
CREATE INDEX idx_citations_quote ON citations USING GIN(to_tsvector('english', quote));

CREATE INDEX idx_processing_logs_document_id ON processing_logs(document_id);
CREATE INDEX idx_processing_logs_batch_id ON processing_logs(batch_id);
CREATE INDEX idx_processing_logs_status ON processing_logs(status);
CREATE INDEX idx_processing_logs_started_at ON processing_logs(started_at DESC);

CREATE INDEX idx_etl_checkpoints_batch_id ON etl_checkpoints(batch_id);
CREATE INDEX idx_etl_checkpoints_type ON etl_checkpoints(checkpoint_type);

CREATE INDEX idx_api_usage_service ON api_usage_metrics(service, endpoint);
CREATE INDEX idx_api_usage_created ON api_usage_metrics(created_at DESC);

-- Create views for common queries
CREATE OR REPLACE VIEW document_processing_status AS
SELECT 
    d.id,
    d.title,
    d.source_path,
    d.file_type,
    d.file_size,
    d.created_at,
    COUNT(DISTINCT c.id) as chunk_count,
    COUNT(DISTINCT ct.id) as citation_count,
    MAX(pl.status) as latest_status,
    MAX(pl.completed_at) as last_processed
FROM documents d
LEFT JOIN chunks c ON d.id = c.document_id
LEFT JOIN citations ct ON c.id = ct.chunk_id
LEFT JOIN processing_logs pl ON d.id = pl.document_id
GROUP BY d.id;

-- Create functions for vector similarity search
CREATE OR REPLACE FUNCTION search_similar_chunks(
    query_embedding vector(768),
    match_count integer DEFAULT 10,
    filter_metadata jsonb DEFAULT '{}'
)
RETURNS TABLE (
    chunk_id uuid,
    document_id uuid,
    content text,
    similarity float,
    metadata jsonb
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.id as chunk_id,
        c.document_id,
        c.content,
        1 - (c.embedding <=> query_embedding) as similarity,
        c.metadata
    FROM chunks c
    WHERE c.metadata @> filter_metadata
    ORDER BY c.embedding <=> query_embedding
    LIMIT match_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get citation with full context
CREATE OR REPLACE FUNCTION get_citation_context(citation_id uuid)
RETURNS TABLE (
    quote text,
    document_title text,
    document_path text,
    s3_url text,
    chunk_content text,
    start_char integer,
    end_char integer
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ct.quote,
        d.title as document_title,
        d.source_path as document_path,
        CONCAT('s3://', d.s3_bucket, '/', d.s3_key) as s3_url,
        c.content as chunk_content,
        c.start_char + ct.start_position as start_char,
        c.start_char + ct.end_position as end_char
    FROM citations ct
    JOIN chunks c ON ct.chunk_id = c.id
    JOIN documents d ON c.document_id = d.id
    WHERE ct.id = citation_id;
END;
$$ LANGUAGE plpgsql;

-- RLS Policies (if needed for multi-tenant access)
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE citations ENABLE ROW LEVEL SECURITY;
ALTER TABLE processing_logs ENABLE ROW LEVEL SECURITY;

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE documents IS 'Stores original document metadata and references to S3 storage';
COMMENT ON TABLE chunks IS 'Document chunks with vector embeddings for semantic search';
COMMENT ON TABLE citations IS 'Exact quotes with character-level positions for citation tracking';
COMMENT ON TABLE processing_logs IS 'ETL pipeline execution logs for monitoring and debugging';
COMMENT ON TABLE etl_checkpoints IS 'Checkpoints for resumable ETL processing';
COMMENT ON TABLE api_usage_metrics IS 'Track API usage and costs for Jina AI and other services';

COMMENT ON COLUMN chunks.embedding IS 'Jina-generated 768-dimensional vector embedding';
COMMENT ON COLUMN documents.hash IS 'SHA256 hash for document deduplication';
COMMENT ON COLUMN citations.confidence IS 'Confidence score for citation accuracy (0-1)';

-- Grant permissions (adjust based on your user setup)
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO authenticated;