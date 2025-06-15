# Pinecone Vector DB
PINECONE_HOST=https://nightingale-dwk2rdy.svc.aped-4627-b74a.pinecone.io
PINECONE_REGION=us-east-1
PINECONE_MODE=Serverless (JINA)
PINECONE_API_KEY_NAME=

# Neo4JS
User Name = neo4j 
Password = 0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE
NEO4J_URI=neo4j+s://82dcab45.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE
NEO4J_DATABASE=neo4j


# JINA EMBEDDINGS/RERANKING/SEARCH/CLASSIFICATION
JINA_API_KEY=2025
JINA_API_KEY_NAME=jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q
JINA_DIMENSIONS=768
JINA_MODELS=
   20      "models": {
     21        "embedding": "jina-embeddings-v2-base-en",
     22        "reranking": "jina-reranker-v1-base-en",
     21        "embedding": "jina-clip-v2",
     22        "reranking": "jina-reranker-v2-base-multilingual",
     23        "classifier": "jina-classifier-v1-base-en",
     24        "deepSearch": "jina-search-v1-base-en"
     25      },


# Supabase 
## Nightingale for Seldon, DT. Restomod 
Project Name = nightingale
Project ID = yopfdfezojpdnpgbolhu
URL = https://yopfdfezojpdnpgbolhu.supabase.co

## Super Password
Tesla457$centR1n0

# Connect to Supabase via Shared Connection Pooler
DATABASE_URL="postgresql://postgres.yopfdfezojpdnpgbolhu:Tesla457$centR1n0@aws-0-us-east-2.pooler.supabase.com:6543/postgres?pgbouncer=true"

## Direct Connection
 (ideal for applications with persistent long lived conenctoins)
 DATABASE_URL=postgresql://postgres:Tesla457$centR1n0@db.yopfdfezojpdnpgbolhu.supabase.co:5432/postgres

## Transaction Pooler ( Ideal for stateless applications like serverless functions where each interaction with Postgres is brief and isolated.)
DATABASE_URL=postgres://postgres:Tesla457$centR1n0@db.yopfdfezojpdnpgbolhu.supabase.co:6543/postgres

## Session Pooler (Only recommended as an alternative to Direct Connection, when connecting via an IPv4 network.)
DATABASE_URL=postgresql://postgres.yopfdfezojpdnpgbolhu:Tesla457$centR1n0@aws-0-us-east-2.pooler.supabase.com:5432/postgres

## Anon_Key
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvcGZkZmV6b2pwZG5wZ2JvbGh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk3ODYxMzUsImV4cCI6MjA2NTM2MjEzNX0.84rUbeqj2U0qyGPsLHZ9ZhxAMCTjRNdcnP54fiHU5yE

## Service Role Secret
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvcGZkZmV6b2pwZG5wZ2JvbGh1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0OTc4NjEzNSwiZXhwIjoyMDY1MzYyMTM1fQ.WDo32wzn0qAmO4i82PEWbqq1a9v1Yu_LmoUVpEuwqkM

## JWT
SUPABASE_JWT_CODE=9mIjR3O5OSOMd9wTH6PAueijk1l3XqwXucnRVXSLGbl3CqVHNhFOyL/I7922/KvaIK7cYeCjCoDlUPgTWUAmCw==

## Supabsse S3 Connection
Storage Bucker Name = nightingale
Endpoint
https://yopfdfezojpdnpgbolhu.supabase.co/storage/v1/s3

### Access Key ID
36a79e18a5787aca71b19d598efc9bbd

### Secret Access Key
1f0767fe5f137ab1024a3beea22b233e453f82c3247ddc78ce4f71e4d341bda9
Clerk with Supabase
Clerk Domain = https://upright-hornet-41.clerk.accounts.dev
Application = Digital Asset Esc.


# CLERK Authentication

How to setup Clerk in Supabase =
https://supabase.com/docs/guides/auth/third-party/clerk

https://clerk.com/docs/integrations/databases/supabase?_gl=1*j8sb3t*_gcl_au*OTIwNDg2OTcwLjE3NDk3ODcwNDg.*_ga*MzQxMzE1Mzc3LjE3NDk3ODcwNDg.*_ga_1WMF5X234K*czE3NDk3ODcwNDckbzEkZzEkdDE3NDk3ODcxMzEkajYwJGwwJGgw


You must add the following conf to the supabse/config.toml
[auth.third_party.clerk]
enabled = true
domain = "example.clerk.accounts.dev"



ENV

# Supabase Database & Storage
## Session Pooler
SESSION_POOLER_URL=postgresql://postgres.yopfdfezojpdnpgbolhu:Tesla457$centR1n0@aws-0-us-east-2.pooler.supabase.com:5432/postgres
DIRECT_URL=postgresql://postgres:Tesla457$centR1n0@db.yopfdfezojpdnpgbolhu.supabase.co:5432/postgres
SUPABASE_URL=https://yopfdfezojpdnpgbolhu.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvcGZkZmV6b2pwZG5wZ2JvbGh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk3ODYxMzUsImV4cCI6MjA2NTM2MjEzNX0.84rUbeqj2U0qyGPsLHZ9ZhxAMCTjRNdcnP54fiHU5yE
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvcGZkZmV6b2pwZG5wZ2JvbGh1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0OTc4NjEzNSwiZXhwIjoyMDY1MzYyMTM1fQ.WDo32wzn0qAmO4i82PEWbqq1a9v1Yu_LmoUVpEuwqkM


# Supabase Storage Configuration
SUPABASE_STORAGE_BUCKET=nightingale
SUPABASE_S3_ENDPOINT=https://yopfdfezojpdnpgbolhu.supabase.co/storage/v1/s3
SUPABASE_S3_REGION=us-east-1
ACCESS_KEY_ID=36a79e18a5787aca71b19d598efc9bbd
SECRET_ACCESS_KEY=1f0767fe5f137ab1024a3beea22b233e453f82c3247ddc78ce4f71e4d341bda9
JWT_SECRET_KEY=9mIjR3O5OSOMd9wTH6PAueijk1l3XqwXucnRVXSLGbl3CqVHNhFOyL/I7922/KvaIK7cYeCjCoDlUPgTWUAmCw==

