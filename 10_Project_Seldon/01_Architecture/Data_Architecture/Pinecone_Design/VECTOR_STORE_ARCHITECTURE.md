# Pinecone Vector Store Architecture for Project Nightingale
## Comprehensive Design for Semantic Intelligence at Scale

**Document Classification**: Technical Architecture Specification  
**Created**: January 11, 2025  
**Version**: 1.0  
**Purpose**: Detailed technical blueprint for Pinecone vector store implementation supporting 670+ intelligence artifacts

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Vector Store Design](#vector-store-design)
4. [Embedding Strategies](#embedding-strategies)
5. [Metadata Schema Design](#metadata-schema-design)
6. [Hybrid Search Patterns](#hybrid-search-patterns)
7. [Neo4j Integration](#neo4j-integration)
8. [Index Management](#index-management)
9. [Real-time Updates](#real-time-updates)
10. [Query Examples](#query-examples)
11. [Performance & Scaling](#performance-scaling)
12. [Cost Optimization](#cost-optimization)
13. [Implementation Roadmap](#implementation-roadmap)

---

## Executive Summary

This document defines the complete Pinecone vector store architecture for Project Nightingale, transforming 670+ static intelligence artifacts into a dynamic, searchable knowledge base. The system will enable:

- **Sub-100ms semantic search** across all intelligence artifacts
- **Multi-modal embeddings** supporting text, tables, and threat diagrams
- **Hybrid search** combining semantic similarity with keyword precision
- **Real-time intelligence updates** from 100,406+ automated sources
- **Deep integration** with Neo4j's 6-hop graph reasoning engine

### Key Innovations

1. **Hierarchical Namespace Strategy**: Separate namespaces for different intelligence types
2. **Composite Embeddings**: Multiple vector representations per document
3. **Temporal Decay Functions**: Time-aware relevance scoring
4. **Cross-Index Federation**: Unified search across multiple specialized indexes

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PINECONE VECTOR STORE ARCHITECTURE            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Data Sources (670+ Artifacts)                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐│
│  │ Executive   │ │   OSINT     │ │   Express   │ │    GTM    ││
│  │ Concierge   │ │Intelligence │ │Attack Briefs│ │ Profiles  ││
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └─────┬─────┘│
│         └────────────────┴────────────────┴─────────────┘      │
│                              │                                  │
│                    ┌─────────▼──────────┐                      │
│                    │ Document Processor │                      │
│                    │ • Chunking        │                      │
│                    │ • Metadata Extract│                      │
│                    │ • Enrichment      │                      │
│                    └─────────┬──────────┘                      │
│                              │                                  │
│                    ┌─────────▼──────────┐                      │
│                    │ Embedding Pipeline │                      │
│                    │ • OpenAI Ada-002  │                      │
│                    │ • Cohere Embed v3 │                      │
│                    │ • Custom Models   │                      │
│                    └─────────┬──────────┘                      │
│                              │                                  │
│  ┌───────────────────────────┴───────────────────────────────┐ │
│  │                    PINECONE INDEXES                        │ │
│  │                                                            │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │ │
│  │  │Intelligence │  │ Prospects   │  │   Threats   │      │ │
│  │  │   Index     │  │   Index     │  │   Index     │      │ │
│  │  │ (1024-dim)  │  │ (1536-dim)  │  │ (768-dim)   │      │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │ │
│  │                                                            │ │
│  └────────────────────────┬──────────────────────────────────┘ │
│                           │                                     │
│                 ┌─────────▼──────────┐                         │
│                 │   Query Engine     │                         │
│                 │ • Semantic Search  │                         │
│                 │ • Hybrid Ranking   │                         │
│                 │ • Reranking       │                         │
│                 └─────────┬──────────┘                         │
│                           │                                     │
│                 ┌─────────▼──────────┐                         │
│                 │ Neo4j Integration  │                         │
│                 │ • Graph Traversal  │                         │
│                 │ • Path Analysis    │                         │
│                 │ • Risk Propagation │                         │
│                 └────────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Vector Store Design

### Multi-Index Architecture

We implement a federated index design optimized for different query patterns:

```yaml
Indexes:
  nightingale-intelligence:
    dimensions: 1024
    metric: cosine
    pods: 2
    replicas: 2
    pod_type: p2.x1
    namespaces:
      - executive_concierge
      - osint_collections
      - threat_landscape
    
  nightingale-prospects:
    dimensions: 1536  # Higher dimension for nuanced similarity
    metric: cosine
    pods: 1
    replicas: 2
    pod_type: p1.x1
    namespaces:
      - energy_sector
      - manufacturing_sector
      - transportation_sector
      - utilities_sector
    
  nightingale-threats:
    dimensions: 768  # Optimized for speed
    metric: dotproduct
    pods: 1
    replicas: 1
    pod_type: s1.x1
    namespaces:
      - threat_actors
      - vulnerabilities
      - attack_patterns
```

### Vector ID Schema

Consistent, hierarchical ID structure for all vectors:

```
Format: {doc_type}_{prospect_id}_{doc_id}_{chunk_id}

Examples:
- exec_A030734_20250111_001  # Executive Concierge chunk
- osint_A030734_intel_002     # OSINT intelligence chunk
- eab_A030734_bauxite_003     # Express Attack Brief chunk
- gtm_A030734_profile_004     # GTM Profile chunk
```

---

## Embedding Strategies

### 1. Document Type-Specific Embeddings

Different document types require different embedding approaches:

```python
class EmbeddingStrategy:
    """Adaptive embedding strategy based on document type"""
    
    STRATEGIES = {
        "executive_concierge": {
            "model": "text-embedding-3-large",
            "dimensions": 1024,
            "chunk_size": 1000,
            "overlap": 200,
            "preprocessing": ["remove_headers", "expand_acronyms"]
        },
        "osint_intelligence": {
            "model": "text-embedding-3-large", 
            "dimensions": 1024,
            "chunk_size": 800,
            "overlap": 150,
            "preprocessing": ["extract_entities", "normalize_dates"]
        },
        "express_attack_brief": {
            "model": "text-embedding-ada-002",
            "dimensions": 1536,
            "chunk_size": 600,
            "overlap": 100,
            "preprocessing": ["extract_iocs", "parse_ttps"]
        },
        "threat_landscape": {
            "model": "cohere-embed-english-v3.0",
            "dimensions": 768,
            "chunk_size": 500,
            "overlap": 50,
            "preprocessing": ["extract_cves", "parse_mitre"]
        }
    }
    
    def embed_document(self, doc_type: str, content: str) -> List[Vector]:
        strategy = self.STRATEGIES[doc_type]
        
        # Preprocess
        processed = self.preprocess(content, strategy["preprocessing"])
        
        # Chunk
        chunks = self.semantic_chunk(
            processed, 
            strategy["chunk_size"], 
            strategy["overlap"]
        )
        
        # Embed
        embeddings = []
        for chunk in chunks:
            embedding = self.generate_embedding(
                chunk,
                model=strategy["model"],
                dimensions=strategy["dimensions"]
            )
            embeddings.append(embedding)
            
        return embeddings
```

### 2. Semantic Chunking Algorithm

Intelligent chunking that preserves context:

```python
def semantic_chunk(text: str, target_size: int, overlap: int) -> List[str]:
    """
    Chunk text semantically, preserving complete thoughts
    """
    # Split on natural boundaries
    sentences = nltk.sent_tokenize(text)
    
    chunks = []
    current_chunk = []
    current_size = 0
    
    for sentence in sentences:
        sentence_tokens = len(tokenizer.encode(sentence))
        
        # If adding sentence exceeds target, start new chunk
        if current_size + sentence_tokens > target_size and current_chunk:
            # Add chunk with overlap from previous
            chunk_text = ' '.join(current_chunk)
            chunks.append(chunk_text)
            
            # Start new chunk with overlap
            overlap_sentences = []
            overlap_size = 0
            
            # Work backwards to create overlap
            for sent in reversed(current_chunk):
                sent_size = len(tokenizer.encode(sent))
                if overlap_size + sent_size <= overlap:
                    overlap_sentences.insert(0, sent)
                    overlap_size += sent_size
                else:
                    break
            
            current_chunk = overlap_sentences + [sentence]
            current_size = overlap_size + sentence_tokens
        else:
            current_chunk.append(sentence)
            current_size += sentence_tokens
    
    # Add final chunk
    if current_chunk:
        chunks.append(' '.join(current_chunk))
    
    return chunks
```

### 3. Multi-Modal Embeddings

Support for tables, diagrams, and structured data:

```python
class MultiModalEmbedder:
    """Generate embeddings for different content types"""
    
    def embed_table(self, table_data: pd.DataFrame) -> np.ndarray:
        """Convert table to embeddings"""
        # Convert table to structured text
        table_text = self.table_to_text(table_data)
        
        # Add column headers as context
        headers = " | ".join(table_data.columns)
        context = f"Table with columns: {headers}\n{table_text}"
        
        return self.embed_text(context)
    
    def embed_threat_diagram(self, mermaid_code: str) -> np.ndarray:
        """Convert threat diagram to embeddings"""
        # Parse mermaid diagram
        nodes, edges = self.parse_mermaid(mermaid_code)
        
        # Create textual representation
        diagram_text = self.diagram_to_text(nodes, edges)
        
        return self.embed_text(diagram_text)
    
    def embed_mitre_mapping(self, techniques: List[str]) -> np.ndarray:
        """Specialized embedding for MITRE ATT&CK techniques"""
        # Expand technique IDs to full descriptions
        expanded = [self.mitre_lookup(tech) for tech in techniques]
        
        # Create weighted embedding
        technique_text = " ".join(expanded)
        
        return self.embed_text(technique_text, weight_keywords=techniques)
```

---

## Metadata Schema Design

### Comprehensive Metadata Structure

Rich metadata enables powerful filtering and analytics:

```typescript
interface VectorMetadata {
  // Core Identifiers
  id: string;                    // Unique vector ID
  doc_id: string;                // Parent document ID
  chunk_index: number;           // Position in document
  
  // Prospect Information
  prospect_id: string;           // e.g., "A-030734"
  company_name: string;          // e.g., "Consumers Energy"
  industry: string;              // e.g., "Energy"
  sector: string;                // e.g., "Critical Infrastructure"
  revenue_range: string;         // e.g., "$1B-$5B"
  employee_count: number;        // e.g., 8000
  
  // Document Classification
  doc_type: DocumentType;        // executive_concierge | osint | eab | gtm
  doc_subtype?: string;          // e.g., "ransomware_analysis"
  created_date: string;          // ISO 8601 date
  last_updated: string;          // ISO 8601 date
  version: number;               // Document version
  
  // Threat Intelligence
  threat_actors: string[];       // e.g., ["BAUXITE", "VOLTZITE"]
  vulnerabilities: string[];     // CVE IDs
  mitre_techniques: string[];    // ATT&CK technique IDs
  threat_severity: number;       // 1-10 scale
  exploited_in_wild: boolean;    
  
  // Technology Stack
  technologies: string[];        // e.g., ["SCADA", "Schneider", "Windows"]
  ot_systems: string[];          // e.g., ["DCS", "PLC", "HMI"]
  cloud_platforms: string[];     // e.g., ["AWS", "Azure"]
  
  // Compliance & Regulatory
  compliance_frameworks: string[]; // e.g., ["NERC-CIP", "IEC-62443"]
  regulatory_requirements: string[]; // Specific requirements
  audit_status?: string;         // Current compliance status
  
  // Service Themes
  primary_theme: ServiceTheme;   // Main service theme
  secondary_themes: ServiceTheme[]; // Additional themes
  use_cases: string[];           // Specific use cases
  
  // Account Management
  account_manager: string;       // Assigned AM
  sales_stage: string;           // Current sales stage
  last_contact?: string;         // Last interaction date
  engagement_score?: number;     // 1-10 engagement level
  
  // Search Optimization
  keywords: string[];            // Extracted keywords
  entities: Entity[];            // Named entities
  summary: string;               // Brief chunk summary
  
  // Quality Metrics
  confidence_score: number;      // 0-1 confidence in data
  source_reliability: string;    // A-F rating
  data_freshness: number;        // Days since last update
  
  // Performance Tracking
  access_count: number;          // Times accessed
  relevance_scores: number[];    // Historical relevance feedback
  avg_relevance: number;         // Average relevance score
}

interface Entity {
  text: string;
  type: 'PERSON' | 'ORG' | 'LOCATION' | 'TECHNOLOGY' | 'THREAT_ACTOR';
  salience: number;
}

enum ServiceTheme {
  RANSOMWARE_RESILIENCE = "ransomware_resilience",
  MA_DUE_DILIGENCE = "m&a_due_diligence",
  ITC_CONVERGENCE = "itc_convergence",
  SUPPLY_CHAIN_ASSURANCE = "supply_chain_assurance",
  BOARD_REPORTING = "board_reporting",
  INCIDENT_RECOVERY = "incident_recovery",
  REGULATORY_COMPLIANCE = "regulatory_compliance",
  INSIDER_THREAT = "insider_threat",
  THIRD_PARTY_RISK = "third_party_risk"
}

enum DocumentType {
  EXECUTIVE_CONCIERGE = "executive_concierge",
  OSINT_INTELLIGENCE = "osint_intelligence",
  EXPRESS_ATTACK_BRIEF = "express_attack_brief",
  GTM_PROFILE = "gtm_profile",
  THREAT_LANDSCAPE = "threat_landscape",
  CASE_STUDY = "case_study",
  TECHNICAL_REPORT = "technical_report"
}
```

### Metadata Extraction Pipeline

```python
class MetadataExtractor:
    """Extract rich metadata from documents"""
    
    def extract_metadata(self, doc_path: str, content: str) -> VectorMetadata:
        metadata = {}
        
        # Extract from filename
        metadata.update(self.parse_filename(doc_path))
        
        # Extract from content
        metadata['entities'] = self.extract_entities(content)
        metadata['keywords'] = self.extract_keywords(content)
        metadata['threat_actors'] = self.extract_threat_actors(content)
        metadata['vulnerabilities'] = self.extract_cves(content)
        metadata['mitre_techniques'] = self.extract_mitre(content)
        
        # Analyze themes
        metadata['primary_theme'] = self.identify_primary_theme(content)
        metadata['secondary_themes'] = self.identify_secondary_themes(content)
        
        # Calculate scores
        metadata['threat_severity'] = self.calculate_threat_severity(metadata)
        metadata['confidence_score'] = self.calculate_confidence(content)
        
        # Add temporal data
        metadata['created_date'] = datetime.now().isoformat()
        metadata['data_freshness'] = 0
        
        return metadata
    
    def extract_threat_actors(self, content: str) -> List[str]:
        """Extract threat actor names using NER and pattern matching"""
        actors = []
        
        # Known threat actor patterns
        known_actors = [
            "BAUXITE", "VOLTZITE", "GRAPHITE", "APT28", "APT29",
            "Lazarus", "FIN7", "Carbanak", "DarkHydrus"
        ]
        
        for actor in known_actors:
            if actor.lower() in content.lower():
                actors.append(actor)
        
        # Use NER for additional actors
        doc = nlp(content)
        for ent in doc.ents:
            if ent.label_ == "ORG" and "APT" in ent.text:
                actors.append(ent.text)
        
        return list(set(actors))
```

---

## Hybrid Search Patterns

### 1. Semantic + Keyword Hybrid Search

Combine the power of semantic understanding with keyword precision:

```python
class HybridSearchEngine:
    """Implement hybrid search combining semantic and keyword search"""
    
    def hybrid_search(
        self,
        query: str,
        semantic_weight: float = 0.7,
        keyword_weight: float = 0.3,
        filters: Dict = None,
        top_k: int = 20
    ) -> List[SearchResult]:
        
        # 1. Semantic search
        semantic_results = self.semantic_search(query, filters, top_k * 2)
        
        # 2. Keyword search
        keyword_results = self.keyword_search(query, filters, top_k * 2)
        
        # 3. Merge and rerank
        merged_results = self.merge_results(
            semantic_results,
            keyword_results,
            semantic_weight,
            keyword_weight
        )
        
        # 4. Apply business logic reranking
        reranked = self.business_rerank(merged_results, query)
        
        return reranked[:top_k]
    
    def semantic_search(self, query: str, filters: Dict, top_k: int):
        """Pure semantic search using embeddings"""
        query_embedding = self.embed_query(query)
        
        results = self.index.query(
            vector=query_embedding,
            filter=filters,
            top_k=top_k,
            include_metadata=True
        )
        
        return results
    
    def keyword_search(self, query: str, filters: Dict, top_k: int):
        """Keyword search using metadata"""
        # Extract keywords from query
        keywords = self.extract_query_keywords(query)
        
        # Build keyword filter
        keyword_filter = {
            "$or": [
                {"keywords": {"$in": keywords}},
                {"summary": {"$contains": keywords}},
                {"technologies": {"$in": keywords}}
            ]
        }
        
        if filters:
            keyword_filter = {"$and": [filters, keyword_filter]}
        
        # Search with dummy vector (metadata only)
        results = self.index.query(
            vector=[0] * self.dimensions,  # Dummy vector
            filter=keyword_filter,
            top_k=top_k,
            include_metadata=True
        )
        
        return results
    
    def business_rerank(self, results: List, query: str) -> List:
        """Apply business logic to rerank results"""
        reranked = []
        
        for result in results:
            score = result.score
            
            # Boost recent documents
            days_old = (datetime.now() - 
                       datetime.fromisoformat(result.metadata['created_date'])).days
            recency_boost = math.exp(-days_old / 30)  # Decay over 30 days
            score *= (1 + 0.2 * recency_boost)
            
            # Boost high-severity threats
            if result.metadata.get('threat_severity', 0) > 8:
                score *= 1.3
            
            # Boost exact company matches
            if query.lower() in result.metadata.get('company_name', '').lower():
                score *= 1.5
            
            # Boost by engagement history
            score *= (1 + 0.1 * result.metadata.get('avg_relevance', 0))
            
            reranked.append((score, result))
        
        # Sort by adjusted score
        reranked.sort(key=lambda x: x[0], reverse=True)
        
        return [r[1] for r in reranked]
```

### 2. Multi-Stage Retrieval Pattern

Implement retrieval in stages for optimal performance:

```python
class MultiStageRetriever:
    """Multi-stage retrieval for complex queries"""
    
    def retrieve(self, query: str, context: Dict = None) -> List[Document]:
        # Stage 1: Broad semantic search (cast a wide net)
        stage1_results = self.broad_search(query, top_k=100)
        
        # Stage 2: Rerank with cross-encoder
        stage2_results = self.cross_encoder_rerank(
            query, 
            stage1_results, 
            top_k=30
        )
        
        # Stage 3: Filter by business context
        stage3_results = self.context_filter(
            stage2_results,
            context,
            top_k=10
        )
        
        # Stage 4: Enrich with graph data
        final_results = self.enrich_with_graph(stage3_results)
        
        return final_results
    
    def cross_encoder_rerank(self, query: str, results: List, top_k: int):
        """Use cross-encoder for precise reranking"""
        pairs = [(query, r.metadata['summary']) for r in results]
        
        scores = self.cross_encoder.predict(pairs)
        
        # Sort by cross-encoder score
        scored_results = list(zip(scores, results))
        scored_results.sort(key=lambda x: x[0], reverse=True)
        
        return [r[1] for r in scored_results[:top_k]]
```

### 3. Contextual Search Patterns

Search patterns that understand context:

```python
class ContextualSearch:
    """Search with deep context understanding"""
    
    def search_with_context(
        self,
        query: str,
        user_context: UserContext,
        session_context: SessionContext
    ) -> List[SearchResult]:
        
        # Expand query with context
        expanded_query = self.expand_query(query, user_context, session_context)
        
        # Build contextual filters
        filters = self.build_contextual_filters(user_context)
        
        # Perform search
        results = self.hybrid_search(expanded_query, filters)
        
        # Post-process based on context
        contextualized = self.contextualize_results(results, session_context)
        
        return contextualized
    
    def expand_query(self, query: str, user: UserContext, session: SessionContext):
        """Expand query based on context"""
        expanded = query
        
        # Add user's focus areas
        if user.primary_industry:
            expanded += f" {user.primary_industry}"
        
        # Add recent search context
        if session.recent_queries:
            related_terms = self.extract_themes(session.recent_queries[-3:])
            expanded += f" {' '.join(related_terms)}"
        
        # Add temporal context
        if "recent" in query.lower() or "latest" in query.lower():
            expanded += f" created after {datetime.now() - timedelta(days=30)}"
        
        return expanded
    
    def build_contextual_filters(self, user: UserContext) -> Dict:
        """Build filters based on user context"""
        filters = {}
        
        # Filter by user's assigned accounts
        if user.account_manager:
            filters['account_manager'] = user.account_manager
        
        # Filter by user's industries
        if user.industries:
            filters['industry'] = {"$in": user.industries}
        
        # Filter by user's clearance level
        if user.clearance_level:
            filters['classification'] = {"$lte": user.clearance_level}
        
        return filters
```

---

## Neo4j Integration

### Unified Intelligence Queries

Combine Pinecone's semantic search with Neo4j's graph traversal:

```python
class UnifiedIntelligenceEngine:
    """Integrate Pinecone semantic search with Neo4j graph analysis"""
    
    def __init__(self, pinecone_index, neo4j_driver):
        self.pinecone = pinecone_index
        self.neo4j = neo4j_driver
        self.cache = TTLCache(maxsize=1000, ttl=3600)
    
    def unified_search(
        self,
        query: str,
        search_type: str = "hybrid",
        graph_depth: int = 6
    ) -> UnifiedResults:
        
        # Step 1: Semantic search in Pinecone
        semantic_results = self.semantic_search(query)
        
        # Step 2: Extract entities for graph search
        entities = self.extract_entities_from_results(semantic_results)
        
        # Step 3: Graph traversal in Neo4j
        graph_results = self.graph_search(entities, depth=graph_depth)
        
        # Step 4: Merge and enrich results
        unified = self.merge_intelligence(semantic_results, graph_results)
        
        # Step 5: Apply unified ranking
        ranked = self.unified_ranking(unified, query)
        
        return ranked
    
    def graph_search(self, entities: List[Entity], depth: int) -> GraphResults:
        """Perform multi-hop graph search"""
        
        with self.neo4j.session() as session:
            # Find all paths between entities
            query = """
            UNWIND $entities as entity
            MATCH (n {name: entity.name})
            CALL apoc.path.expandConfig(n, {
                maxLevel: $depth,
                relationshipFilter: "TARGETS|EXPLOITS|AFFECTS|SUPPLIES_TO",
                uniqueness: "RELATIONSHIP_PATH"
            }) YIELD path
            WHERE length(path) > 0
            RETURN path, 
                   [node in nodes(path) | node.name] as node_names,
                   [rel in relationships(path) | type(rel)] as rel_types,
                   reduce(risk = 1.0, r in relationships(path) | 
                          risk * coalesce(r.probability, 0.5)) as path_risk
            ORDER BY path_risk DESC
            LIMIT 50
            """
            
            result = session.run(query, entities=entities, depth=depth)
            
            return self.process_graph_results(result)
    
    def merge_intelligence(
        self,
        semantic: List[SemanticResult],
        graph: List[GraphResult]
    ) -> List[UnifiedResult]:
        """Merge semantic and graph results"""
        
        unified = []
        
        # Create a map of entities to graph paths
        entity_paths = defaultdict(list)
        for g in graph:
            for entity in g.entities:
                entity_paths[entity].append(g)
        
        # Enrich semantic results with graph context
        for s in semantic:
            result = UnifiedResult(
                content=s.content,
                score=s.score,
                metadata=s.metadata,
                graph_paths=[],
                risk_score=0
            )
            
            # Find relevant graph paths
            for entity in s.entities:
                if entity in entity_paths:
                    result.graph_paths.extend(entity_paths[entity])
                    
            # Calculate unified risk score
            if result.graph_paths:
                result.risk_score = max(p.path_risk for p in result.graph_paths)
            
            unified.append(result)
        
        return unified
    
    def unified_ranking(
        self,
        results: List[UnifiedResult],
        query: str
    ) -> List[UnifiedResult]:
        """Apply unified ranking algorithm"""
        
        scored_results = []
        
        for result in results:
            # Base score from semantic search
            score = result.score
            
            # Graph connectivity bonus
            connectivity_score = len(result.graph_paths) * 0.1
            score += min(connectivity_score, 0.5)  # Cap at 0.5
            
            # Risk-based boost
            if result.risk_score > 0.8:
                score *= 1.5
            elif result.risk_score > 0.6:
                score *= 1.2
            
            # Threat severity boost
            severity = result.metadata.get('threat_severity', 0)
            score *= (1 + severity / 20)
            
            # Recency boost
            days_old = (datetime.now() - 
                       datetime.fromisoformat(result.metadata['created_date'])).days
            recency_factor = math.exp(-days_old / 60)
            score *= (1 + 0.3 * recency_factor)
            
            scored_results.append((score, result))
        
        # Sort by unified score
        scored_results.sort(key=lambda x: x[0], reverse=True)
        
        return [r[1] for r in scored_results]
```

### Graph-Enhanced Embeddings

Enrich embeddings with graph context:

```python
class GraphEnhancedEmbedder:
    """Enhance embeddings with graph structure information"""
    
    def create_enhanced_embedding(
        self,
        content: str,
        entity: str,
        neo4j_session
    ) -> np.ndarray:
        
        # Get base embedding
        base_embedding = self.embed_text(content)
        
        # Get graph context
        graph_context = self.get_graph_context(entity, neo4j_session)
        
        # Create graph embedding
        graph_embedding = self.embed_graph_context(graph_context)
        
        # Combine embeddings
        enhanced = self.combine_embeddings(
            base_embedding,
            graph_embedding,
            weights=[0.7, 0.3]
        )
        
        return enhanced
    
    def get_graph_context(self, entity: str, session) -> GraphContext:
        """Extract graph neighborhood as context"""
        
        query = """
        MATCH (n {name: $entity})
        OPTIONAL MATCH (n)-[r1]-(neighbor1)
        OPTIONAL MATCH (neighbor1)-[r2]-(neighbor2)
        WHERE neighbor2 <> n
        RETURN 
            n,
            collect(DISTINCT {
                node: neighbor1.name,
                rel: type(r1),
                properties: properties(r1)
            }) as first_degree,
            collect(DISTINCT {
                node: neighbor2.name,
                rel: type(r2)
            }) as second_degree
        """
        
        result = session.run(query, entity=entity).single()
        
        return GraphContext(
            entity=result['n'],
            first_degree=result['first_degree'],
            second_degree=result['second_degree']
        )
    
    def embed_graph_context(self, context: GraphContext) -> np.ndarray:
        """Convert graph context to embedding"""
        
        # Create textual representation
        context_text = f"Entity: {context.entity['name']}\n"
        
        # Add first-degree connections
        for conn in context.first_degree[:10]:  # Limit to top 10
            context_text += f"- {conn['rel']} -> {conn['node']}\n"
        
        # Add second-degree patterns
        rel_counts = Counter(c['rel'] for c in context.second_degree)
        context_text += f"Second-degree patterns: {dict(rel_counts)}\n"
        
        # Generate embedding
        return self.embed_text(context_text)
```

---

## Index Management

### Index Configuration and Optimization

```python
class IndexManager:
    """Manage Pinecone indexes for optimal performance"""
    
    def __init__(self, api_key: str):
        self.pc = Pinecone(api_key=api_key)
        self.indexes = {}
        
    def create_optimized_index(
        self,
        name: str,
        dimension: int,
        metric: str = "cosine",
        pods: int = 1,
        pod_type: str = "p1.x1"
    ):
        """Create index with optimized settings"""
        
        # Calculate optimal settings based on expected volume
        if dimension > 1000:
            pod_type = "p2.x1"  # More memory for high dimensions
        
        self.pc.create_index(
            name=name,
            dimension=dimension,
            metric=metric,
            pods=pods,
            pod_type=pod_type,
            metadata_config={
                "indexed": [
                    "company_name",
                    "industry", 
                    "threat_actors",
                    "doc_type",
                    "primary_theme"
                ]
            }
        )
        
        # Wait for index to be ready
        self._wait_for_index(name)
        
        # Configure index
        index = self.pc.Index(name)
        self.indexes[name] = index
        
        return index
    
    def optimize_index_performance(self, index_name: str):
        """Optimize index for query performance"""
        
        index = self.indexes[index_name]
        stats = index.describe_index_stats()
        
        # Analyze current performance
        total_vectors = stats.total_vector_count
        dimensions = stats.dimension
        
        # Recommend optimizations
        optimizations = []
        
        if total_vectors > 1_000_000:
            optimizations.append({
                "action": "scale_up",
                "reason": "High vector count",
                "recommendation": "Increase to 2 pods"
            })
        
        if dimensions > 1024:
            optimizations.append({
                "action": "use_p2_pods",
                "reason": "High dimensionality",
                "recommendation": "Upgrade to p2.x1 pods"
            })
        
        # Check query patterns
        if self._analyze_query_patterns(index_name):
            optimizations.append({
                "action": "add_replicas",
                "reason": "High query volume",
                "recommendation": "Add 2 replicas"
            })
        
        return optimizations
    
    def manage_namespaces(self, index_name: str):
        """Manage namespaces for logical separation"""
        
        index = self.indexes[index_name]
        
        # Define namespace strategy
        namespaces = {
            "executive_concierge": {
                "filter": {"doc_type": "executive_concierge"},
                "description": "Executive-level intelligence reports"
            },
            "threat_intelligence": {
                "filter": {"doc_type": {"$in": ["osint", "threat_landscape"]}},
                "description": "Threat actor and vulnerability intelligence"
            },
            "gtm_profiles": {
                "filter": {"doc_type": "gtm_profile"},
                "description": "Go-to-market prospect profiles"
            }
        }
        
        # Create namespace metadata
        for ns_name, ns_config in namespaces.items():
            self._configure_namespace(index, ns_name, ns_config)
        
        return namespaces
```

### Index Monitoring and Maintenance

```python
class IndexMonitor:
    """Monitor and maintain index health"""
    
    def __init__(self, index_manager: IndexManager):
        self.manager = index_manager
        self.metrics = defaultdict(list)
        
    def monitor_index_health(self, index_name: str) -> HealthReport:
        """Comprehensive index health check"""
        
        index = self.manager.indexes[index_name]
        stats = index.describe_index_stats()
        
        health = HealthReport()
        
        # Check vector count
        health.total_vectors = stats.total_vector_count
        health.vectors_per_namespace = stats.namespaces
        
        # Check index fullness
        health.index_fullness = stats.index_fullness
        if health.index_fullness > 0.9:
            health.add_warning("Index approaching capacity")
        
        # Check dimension consistency
        if stats.dimension != self.expected_dimensions[index_name]:
            health.add_error("Dimension mismatch detected")
        
        # Performance metrics
        health.avg_query_latency = self._get_avg_latency(index_name)
        if health.avg_query_latency > 100:  # ms
            health.add_warning("High query latency detected")
        
        return health
    
    def automated_maintenance(self, index_name: str):
        """Perform automated maintenance tasks"""
        
        # 1. Clean up old vectors
        self._cleanup_stale_vectors(index_name)
        
        # 2. Rebalance namespaces
        self._rebalance_namespaces(index_name)
        
        # 3. Update metadata indices
        self._refresh_metadata_indices(index_name)
        
        # 4. Optimize for common queries
        self._optimize_for_patterns(index_name)
    
    def _cleanup_stale_vectors(self, index_name: str):
        """Remove vectors older than retention period"""
        
        index = self.manager.indexes[index_name]
        cutoff_date = datetime.now() - timedelta(days=365)
        
        # Delete in batches
        delete_filter = {
            "last_updated": {"$lt": cutoff_date.isoformat()}
        }
        
        index.delete(filter=delete_filter)
```

---

## Real-time Updates

### Streaming Intelligence Pipeline

```python
class RealTimeIntelligencePipeline:
    """Process and index intelligence in real-time"""
    
    def __init__(self, pinecone_index, kafka_config):
        self.index = pinecone_index
        self.consumer = KafkaConsumer(**kafka_config)
        self.processor = IntelligenceProcessor()
        self.batch_size = 100
        self.batch_timeout = 60  # seconds
        
    async def start_pipeline(self):
        """Start consuming and indexing intelligence"""
        
        batch = []
        last_flush = time.time()
        
        async for message in self.consumer:
            # Parse intelligence update
            update = self.parse_message(message)
            
            # Process and create vectors
            vectors = await self.process_intelligence(update)
            batch.extend(vectors)
            
            # Flush batch if needed
            if len(batch) >= self.batch_size or \
               time.time() - last_flush > self.batch_timeout:
                await self.flush_batch(batch)
                batch = []
                last_flush = time.time()
    
    async def process_intelligence(self, update: IntelligenceUpdate) -> List[Vector]:
        """Process intelligence update into vectors"""
        
        vectors = []
        
        # Extract content based on update type
        if update.type == "vulnerability":
            content = self.processor.process_vulnerability(update)
        elif update.type == "threat_actor":
            content = self.processor.process_threat_actor(update)
        elif update.type == "incident":
            content = self.processor.process_incident(update)
        else:
            content = self.processor.process_generic(update)
        
        # Chunk and embed
        chunks = self.chunk_content(content)
        
        for i, chunk in enumerate(chunks):
            # Generate embedding
            embedding = await self.embed_async(chunk)
            
            # Create metadata
            metadata = self.create_update_metadata(update, chunk, i)
            
            # Create vector
            vector = {
                "id": f"{update.id}_{i}",
                "values": embedding,
                "metadata": metadata
            }
            
            vectors.append(vector)
        
        return vectors
    
    async def flush_batch(self, batch: List[Vector]):
        """Flush vector batch to Pinecone"""
        
        if not batch:
            return
            
        try:
            # Upsert to Pinecone
            self.index.upsert(vectors=batch, async_req=True)
            
            # Log success
            logger.info(f"Flushed {len(batch)} vectors to index")
            
            # Update metrics
            self.metrics.vectors_indexed += len(batch)
            
        except Exception as e:
            logger.error(f"Failed to flush batch: {e}")
            # Implement retry logic
            await self.retry_flush(batch)
```

### Temporal Decay and Updates

```python
class TemporalIntelligenceManager:
    """Manage time-sensitive intelligence with decay"""
    
    def __init__(self, index: pinecone.Index):
        self.index = index
        self.decay_rates = {
            "vulnerability": 0.01,      # Slow decay
            "threat_actor": 0.05,       # Medium decay  
            "incident": 0.1,            # Fast decay
            "executive_concierge": 0.001 # Very slow decay
        }
    
    def apply_temporal_decay(self):
        """Apply temporal decay to all vectors"""
        
        # Iterate through namespaces
        for namespace in self.index.list_namespaces():
            self._decay_namespace(namespace)
    
    def _decay_namespace(self, namespace: str):
        """Apply decay to vectors in namespace"""
        
        # Fetch vectors in batches
        batch_size = 1000
        
        for ids in self._batch_ids(namespace, batch_size):
            # Fetch vectors
            vectors = self.index.fetch(ids=ids, namespace=namespace)
            
            # Apply decay
            updated_vectors = []
            for id, vector in vectors.items():
                # Calculate age
                created = datetime.fromisoformat(
                    vector.metadata['created_date']
                )
                age_days = (datetime.now() - created).days
                
                # Get decay rate
                doc_type = vector.metadata.get('doc_type', 'default')
                decay_rate = self.decay_rates.get(doc_type, 0.01)
                
                # Calculate decay factor
                decay_factor = math.exp(-decay_rate * age_days)
                
                # Update metadata with decay
                vector.metadata['relevance_decay'] = decay_factor
                vector.metadata['effective_score'] = (
                    vector.metadata.get('base_score', 1.0) * decay_factor
                )
                
                updated_vectors.append(vector)
            
            # Update vectors
            self.index.upsert(vectors=updated_vectors, namespace=namespace)
    
    def refresh_intelligence(self, entity: str, new_data: Dict):
        """Refresh intelligence for specific entity"""
        
        # Find existing vectors
        existing = self.index.query(
            vector=[0] * 1024,  # Dummy vector
            filter={"entity": entity},
            top_k=100,
            include_metadata=True
        )
        
        # Update or create new vectors
        for match in existing.matches:
            # Update metadata
            match.metadata.update(new_data)
            match.metadata['last_updated'] = datetime.now().isoformat()
            match.metadata['update_count'] = match.metadata.get('update_count', 0) + 1
            
            # Re-index if content changed
            if 'content' in new_data:
                new_embedding = self.embed(new_data['content'])
                self.index.upsert(
                    vectors=[{
                        "id": match.id,
                        "values": new_embedding,
                        "metadata": match.metadata
                    }]
                )
```

---

## Query Examples

### 1. Executive Intelligence Briefing Query

```python
# Query: "What are the top threats to energy companies this week?"

def executive_threat_briefing(am_name: str) -> List[ThreatBriefing]:
    # Build query
    query = """
    Latest critical threats targeting energy sector companies 
    with active exploitation and high impact potential
    """
    
    # Set filters
    filters = {
        "$and": [
            {"industry": "Energy"},
            {"created_date": {"$gte": (datetime.now() - timedelta(days=7)).isoformat()}},
            {"threat_severity": {"$gte": 8}},
            {"account_manager": am_name}
        ]
    }
    
    # Perform hybrid search
    results = hybrid_search(
        query=query,
        filters=filters,
        semantic_weight=0.6,
        keyword_weight=0.4,
        top_k=10
    )
    
    # Enrich with graph data
    for result in results:
        # Get affected companies
        companies = neo4j_query(f"""
            MATCH (t:ThreatActor {{name: '{result.threat_actor}'}})-[:TARGETS]->(c:Company)
            WHERE c.industry = 'Energy'
            RETURN c.name, c.revenue, c.employee_count
            LIMIT 5
        """)
        
        result.affected_companies = companies
        
        # Get attack timeline
        timeline = neo4j_query(f"""
            MATCH (t:ThreatActor {{name: '{result.threat_actor}'}})-[:EXECUTED]->(a:Attack)
            WHERE a.date > date() - duration('P30D')
            RETURN a.date, a.target, a.impact
            ORDER BY a.date DESC
        """)
        
        result.attack_timeline = timeline
    
    return results

# Example Result:
{
    "threat": "BAUXITE Ransomware Campaign",
    "severity": 9.2,
    "summary": "Active campaign targeting energy sector SCADA systems",
    "affected_companies": [
        {"name": "Regional Power Co", "revenue": "$2.3B", "employees": 5000},
        {"name": "City Water Utility", "revenue": "$450M", "employees": 1200}
    ],
    "attack_timeline": [
        {"date": "2025-01-10", "target": "Gas Pipeline Ltd", "impact": "$5M ransom"},
        {"date": "2025-01-08", "target": "Power Grid Corp", "impact": "48hr outage"}
    ],
    "recommendations": "Immediate patching of CVE-2024-1234, implement MFA on all SCADA access"
}
```

### 2. Supply Chain Risk Discovery Query

```python
# Query: "Find hidden supply chain risks for Consumers Energy"

def supply_chain_risk_analysis(company: str) -> SupplyChainAnalysis:
    # Step 1: Find company's technology stack
    tech_stack = semantic_search(
        query=f"Technology systems used by {company}",
        filter={"company_name": company},
        top_k=20
    )
    
    # Extract technologies
    technologies = extract_technologies(tech_stack)
    
    # Step 2: Find vendors for these technologies
    vendor_query = f"Software vendors and suppliers for {' '.join(technologies)}"
    vendors = semantic_search(vendor_query, top_k=30)
    
    # Step 3: Graph analysis for supply chain paths
    supply_chain_risks = neo4j_query(f"""
        MATCH (c:Company {{name: '{company}'}})
        MATCH path = (c)-[:USES]->(t:Technology)<-[:SUPPLIES]-(v:Vendor)
        OPTIONAL MATCH (v)<-[:COMPROMISED]-(ta:ThreatActor)
        OPTIONAL MATCH (v)-[:HAS_VULNERABILITY]->(vuln:Vulnerability)
        WHERE vuln.severity >= 7
        RETURN 
            v.name as vendor,
            t.name as technology,
            collect(DISTINCT ta.name) as threat_actors,
            collect(DISTINCT vuln.cve) as vulnerabilities,
            length(path) as supply_chain_depth,
            CASE 
                WHEN size(collect(ta)) > 0 THEN 'CRITICAL'
                WHEN size(collect(vuln)) > 3 THEN 'HIGH'
                WHEN size(collect(vuln)) > 0 THEN 'MEDIUM'
                ELSE 'LOW'
            END as risk_level
        ORDER BY risk_level DESC
    """)
    
    # Step 4: Enrich with intelligence
    for risk in supply_chain_risks:
        # Get recent incidents
        incidents = semantic_search(
            f"Security incidents involving {risk['vendor']}",
            filter={
                "doc_type": "incident_report",
                "created_date": {"$gte": (datetime.now() - timedelta(days=90)).isoformat()}
            },
            top_k=5
        )
        
        risk['recent_incidents'] = incidents
        
        # Calculate composite risk score
        risk['composite_score'] = calculate_risk_score(risk)
    
    return SupplyChainAnalysis(
        company=company,
        total_vendors=len(supply_chain_risks),
        critical_risks=len([r for r in supply_chain_risks if r['risk_level'] == 'CRITICAL']),
        supply_chain_map=create_visual_map(supply_chain_risks),
        recommendations=generate_recommendations(supply_chain_risks)
    )

# Example Result:
{
    "company": "Consumers Energy",
    "total_vendors": 47,
    "critical_risks": 3,
    "top_risks": [
        {
            "vendor": "SCADA Solutions Inc",
            "technology": "Schneider Electric SCADA",
            "threat_actors": ["VOLTZITE", "GRAPHITE"],
            "vulnerabilities": ["CVE-2024-1234", "CVE-2024-5678"],
            "risk_level": "CRITICAL",
            "recent_incidents": ["Ransomware attack on German utility (Dec 2024)"],
            "composite_score": 9.4
        }
    ],
    "recommendations": [
        "Immediate security assessment of SCADA Solutions Inc",
        "Implement additional monitoring on Schneider SCADA systems",
        "Consider backup vendor for critical SCADA components"
    ]
}
```

### 3. Competitive Intelligence Query

```python
# Query: "What cybersecurity initiatives are my competitors implementing?"

def competitive_intelligence(industry: str, exclude_company: str) -> CompetitiveAnalysis:
    # Find competitors
    competitors = semantic_search(
        f"Major {industry} companies cybersecurity programs and initiatives",
        filter={
            "$and": [
                {"industry": industry},
                {"company_name": {"$ne": exclude_company}},
                {"doc_type": {"$in": ["osint", "executive_concierge", "news"]}}
            ]
        },
        top_k=50
    )
    
    # Extract initiatives
    initiatives = defaultdict(list)
    
    for comp in competitors:
        company = comp.metadata['company_name']
        
        # Extract cybersecurity initiatives
        if "zero trust" in comp.content.lower():
            initiatives[company].append({
                "initiative": "Zero Trust Implementation",
                "maturity": extract_maturity_level(comp.content),
                "timeline": extract_timeline(comp.content)
            })
        
        if "soc modernization" in comp.content.lower():
            initiatives[company].append({
                "initiative": "SOC Modernization",
                "details": extract_details(comp.content, "soc")
            })
        
        # Check for compliance achievements
        compliance = extract_compliance_mentions(comp.content)
        if compliance:
            initiatives[company].append({
                "initiative": "Compliance Achievement",
                "frameworks": compliance
            })
    
    # Analyze trends
    trend_analysis = analyze_industry_trends(initiatives)
    
    # Generate insights
    return CompetitiveAnalysis(
        industry=industry,
        companies_analyzed=len(initiatives),
        leading_initiatives=get_top_initiatives(initiatives),
        maturity_comparison=compare_maturity_levels(initiatives),
        investment_trends=extract_investment_patterns(competitors),
        recommendations=generate_competitive_recommendations(initiatives, exclude_company)
    )

# Example Result:
{
    "industry": "Energy",
    "companies_analyzed": 12,
    "leading_initiatives": [
        {
            "initiative": "Zero Trust Architecture",
            "adoption_rate": "67%",
            "leaders": ["Duke Energy", "Exelon"]
        },
        {
            "initiative": "OT/IT Convergence",
            "adoption_rate": "45%",
            "leaders": ["Southern Company"]
        }
    ],
    "maturity_comparison": {
        "your_company": 3.2,
        "industry_average": 3.8,
        "industry_leader": 4.6
    },
    "recommendations": [
        "Accelerate Zero Trust implementation to match industry leaders",
        "Consider OT/IT convergence initiative - 45% of competitors have started",
        "Explore AI-powered threat detection - emerging trend with 25% adoption"
    ]
}
```

### 4. M&A Due Diligence Query

```python
# Query: "Cybersecurity risk assessment for potential acquisition of Regional Power Corp"

def ma_due_diligence(target_company: str) -> DueDiligenceReport:
    # Comprehensive security posture search
    security_posture = semantic_search(
        f"{target_company} cybersecurity incidents vulnerabilities compliance data breaches",
        filter={"company_name": target_company},
        top_k=100
    )
    
    # Historical incident analysis
    incidents = extract_incidents(security_posture)
    
    # Technology debt assessment
    tech_debt = neo4j_query(f"""
        MATCH (c:Company {{name: '{target_company}'}})-[:USES]->(t:Technology)
        OPTIONAL MATCH (t)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (t)-[:END_OF_LIFE]->(eol:Date)
        RETURN 
            t.name as technology,
            t.version as version,
            count(v) as vulnerability_count,
            max(v.severity) as max_severity,
            eol.date as end_of_life,
            CASE 
                WHEN eol.date < date() THEN 'CRITICAL'
                WHEN count(v) > 10 THEN 'HIGH'
                WHEN max(v.severity) > 8 THEN 'HIGH'
                ELSE 'MEDIUM'
            END as risk_level
        ORDER BY risk_level DESC
    """)
    
    # Compliance gap analysis
    compliance_gaps = analyze_compliance(security_posture, target_company)
    
    # Calculate acquisition risk score
    risk_score = calculate_ma_risk_score(
        incidents=incidents,
        tech_debt=tech_debt,
        compliance_gaps=compliance_gaps
    )
    
    # Estimate remediation costs
    remediation_estimate = estimate_remediation_costs(
        tech_debt=tech_debt,
        compliance_gaps=compliance_gaps,
        company_size=get_company_size(target_company)
    )
    
    return DueDiligenceReport(
        target=target_company,
        overall_risk_score=risk_score,
        incident_history={
            "last_12_months": len([i for i in incidents if i.recent]),
            "total_incidents": len(incidents),
            "data_breaches": len([i for i in incidents if i.type == 'breach']),
            "ransomware": len([i for i in incidents if i.type == 'ransomware'])
        },
        technology_debt={
            "critical_systems": len([t for t in tech_debt if t['risk_level'] == 'CRITICAL']),
            "total_vulnerabilities": sum(t['vulnerability_count'] for t in tech_debt),
            "end_of_life_systems": len([t for t in tech_debt if t['end_of_life']])
        },
        compliance_status=compliance_gaps,
        estimated_remediation_cost=remediation_estimate,
        key_risks=identify_key_risks(incidents, tech_debt, compliance_gaps),
        recommendations=generate_ma_recommendations(risk_score, remediation_estimate)
    )

# Example Result:
{
    "target": "Regional Power Corp",
    "overall_risk_score": 7.8,
    "incident_history": {
        "last_12_months": 3,
        "total_incidents": 12,
        "data_breaches": 1,
        "ransomware": 2
    },
    "technology_debt": {
        "critical_systems": 4,
        "total_vulnerabilities": 127,
        "end_of_life_systems": 6
    },
    "compliance_status": {
        "nerc_cip": "Partial (72%)",
        "iec_62443": "Non-compliant",
        "sox": "Compliant"
    },
    "estimated_remediation_cost": "$4.2M - $6.8M",
    "key_risks": [
        "Outdated SCADA systems with known vulnerabilities",
        "Recent ransomware incident indicates security gaps",
        "Non-compliance with IEC-62443 poses regulatory risk"
    ],
    "recommendations": [
        "Budget $5M for immediate security remediation",
        "Require security improvements as condition of acquisition",
        "Negotiate $2M price reduction based on security debt"
    ]
}
```

### 5. Threat Prediction Query

```python
# Query: "Predict next likely targets for BAUXITE threat actor"

def predict_threat_targets(threat_actor: str) -> ThreatPrediction:
    # Get threat actor profile and history
    actor_profile = semantic_search(
        f"{threat_actor} targeting patterns victims techniques timeline",
        filter={"threat_actors": threat_actor},
        top_k=50
    )
    
    # Extract historical targets
    historical_targets = extract_targets(actor_profile)
    
    # Analyze patterns
    patterns = neo4j_query(f"""
        MATCH (ta:ThreatActor {{name: '{threat_actor}'}})-[:TARGETED]->(victim:Company)
        WITH victim, victim.industry as industry, victim.revenue as revenue, 
             victim.employee_count as employees, victim.technologies as tech
        RETURN 
            avg(revenue) as avg_revenue,
            collect(DISTINCT industry) as industries,
            avg(employees) as avg_employees,
            reduce(techs = [], t in collect(tech) | techs + t) as common_tech
        
        // Find similar companies not yet targeted
        WITH avg_revenue, industries, avg_employees, common_tech
        MATCH (prospect:Company)
        WHERE NOT exists((ta)-[:TARGETED]->(prospect))
          AND prospect.industry IN industries
          AND prospect.revenue > avg_revenue * 0.8
          AND prospect.revenue < avg_revenue * 1.2
          AND any(t IN prospect.technologies WHERE t IN common_tech)
        RETURN 
            prospect.name as company,
            prospect.industry as industry,
            prospect.revenue as revenue,
            size([t IN prospect.technologies WHERE t IN common_tech]) as tech_matches,
            CASE 
                WHEN prospect.recent_vulnerabilities > 5 THEN 0.3
                ELSE 0
            END +
            CASE
                WHEN prospect.security_score < 5 THEN 0.3
                ELSE 0
            END +
            toFloat(tech_matches) / size(common_tech) * 0.4 as likelihood_score
        ORDER BY likelihood_score DESC
        LIMIT 10
    """)
    
    # Enhance with temporal analysis
    temporal_pattern = analyze_temporal_pattern(historical_targets)
    
    # Calculate time to next attack
    predicted_timeframe = predict_attack_timeframe(temporal_pattern)
    
    # Generate prediction report
    return ThreatPrediction(
        threat_actor=threat_actor,
        prediction_confidence=calculate_confidence(patterns, temporal_pattern),
        likely_targets=[
            {
                "company": p['company'],
                "likelihood": p['likelihood_score'],
                "risk_factors": identify_risk_factors(p),
                "estimated_timeframe": apply_temporal_adjustment(
                    predicted_timeframe, 
                    p['likelihood_score']
                )
            } for p in patterns
        ],
        attack_patterns={
            "preferred_vulnerabilities": extract_preferred_cves(actor_profile),
            "typical_ransom": calculate_typical_ransom(historical_targets),
            "dwell_time": calculate_average_dwell_time(historical_targets)
        },
        recommendations=generate_prediction_recommendations(patterns)
    )

# Example Result:
{
    "threat_actor": "BAUXITE",
    "prediction_confidence": 0.84,
    "likely_targets": [
        {
            "company": "Midwest Power Cooperative",
            "likelihood": 0.89,
            "risk_factors": [
                "Uses same Schneider SCADA as previous victims",
                "Revenue profile matches targeting pattern",
                "Recent vulnerabilities detected"
            ],
            "estimated_timeframe": "15-30 days"
        },
        {
            "company": "Regional Water Authority",
            "likelihood": 0.76,
            "risk_factors": [
                "Critical infrastructure in preferred geography",
                "Outdated security controls"
            ],
            "estimated_timeframe": "30-45 days"
        }
    ],
    "attack_patterns": {
        "preferred_vulnerabilities": ["CVE-2024-1234", "CVE-2023-5678"],
        "typical_ransom": "$2.5M - $5M",
        "dwell_time": "14 days average"
    },
    "recommendations": [
        "Alert Midwest Power Cooperative immediately",
        "Share threat intelligence with predicted targets",
        "Focus patching on CVE-2024-1234 across all clients"
    ]
}
```

---

## Performance & Scaling

### Performance Benchmarks

```yaml
Query Performance Targets:
  semantic_search:
    p50: 50ms
    p95: 100ms
    p99: 200ms
  
  hybrid_search:
    p50: 75ms
    p95: 150ms
    p99: 300ms
  
  graph_enhanced_search:
    p50: 200ms
    p95: 500ms
    p99: 1000ms

Throughput Targets:
  queries_per_second: 1000
  concurrent_queries: 100
  index_updates_per_second: 500

Scale Limits:
  max_vectors_per_index: 10M
  max_metadata_size: 40KB
  max_dimension: 2048
  max_namespaces: 100
```

### Scaling Strategies

```python
class ScalingStrategy:
    """Implement horizontal and vertical scaling"""
    
    def scale_for_growth(self, current_metrics: Metrics) -> ScalingPlan:
        plan = ScalingPlan()
        
        # Vertical scaling (bigger pods)
        if current_metrics.avg_latency > 100:
            plan.add_action("upgrade_pods", {
                "from": "p1.x1",
                "to": "p2.x1",
                "reason": "High latency"
            })
        
        # Horizontal scaling (more pods)
        if current_metrics.qps > 800:
            plan.add_action("add_pods", {
                "current": 1,
                "target": 2,
                "reason": "High query volume"
            })
        
        # Index sharding
        if current_metrics.total_vectors > 5_000_000:
            plan.add_action("shard_index", {
                "strategy": "by_industry",
                "shard_count": 4,
                "reason": "Large vector count"
            })
        
        # Caching layer
        if current_metrics.repeat_query_rate > 0.3:
            plan.add_action("add_cache", {
                "type": "Redis",
                "ttl": 3600,
                "reason": "High repeat query rate"
            })
        
        return plan
```

### Query Optimization Techniques

```python
class QueryOptimizer:
    """Optimize queries for performance"""
    
    def optimize_query(self, query: Query) -> OptimizedQuery:
        optimized = query.copy()
        
        # 1. Metadata pre-filtering
        if query.has_metadata_filters():
            optimized.use_metadata_prefilter = True
            
        # 2. Namespace routing
        if query.can_determine_namespace():
            optimized.target_namespace = self.determine_namespace(query)
            
        # 3. Approximate search for large result sets
        if query.top_k > 100:
            optimized.use_approximate_search = True
            optimized.probe_ratio = 0.1
            
        # 4. Batch similar queries
        if self.can_batch(query):
            optimized.batch_id = self.get_batch_id(query)
            
        # 5. Cache frequent queries
        cache_key = self.generate_cache_key(query)
        if self.is_cacheable(query):
            optimized.cache_key = cache_key
            optimized.cache_ttl = 3600
            
        return optimized
```

---

## Cost Optimization

### Storage Optimization

```python
class StorageOptimizer:
    """Optimize storage costs"""
    
    def optimize_storage(self) -> StorageReport:
        optimizations = []
        
        # 1. Dimension reduction where possible
        optimizations.append({
            "action": "reduce_dimensions",
            "indexes": ["nightingale-threats"],
            "from": 1536,
            "to": 768,
            "savings": "$120/month",
            "impact": "Minimal for threat data"
        })
        
        # 2. Metadata compression
        optimizations.append({
            "action": "compress_metadata",
            "technique": "Remove redundant fields",
            "savings": "$80/month",
            "impact": "None"
        })
        
        # 3. Inactive vector archival
        optimizations.append({
            "action": "archive_inactive",
            "criteria": "Not accessed in 90 days",
            "target": "S3 cold storage",
            "savings": "$200/month"
        })
        
        # 4. Deduplication
        optimizations.append({
            "action": "deduplicate",
            "method": "Content hash comparison",
            "estimated_duplicates": "5%",
            "savings": "$50/month"
        })
        
        return StorageReport(
            current_cost="$2,400/month",
            optimized_cost="$1,950/month",
            savings="$450/month (18.75%)",
            optimizations=optimizations
        )
```

### Query Cost Management

```python
class QueryCostManager:
    """Manage and optimize query costs"""
    
    def __init__(self):
        self.query_cache = TTLCache(maxsize=10000, ttl=3600)
        self.query_patterns = defaultdict(int)
        
    def optimize_query_costs(self) -> CostReport:
        # Analyze query patterns
        patterns = self.analyze_patterns()
        
        # Implement cost optimizations
        optimizations = []
        
        # 1. Cache frequent queries
        if patterns['repeat_rate'] > 0.2:
            optimizations.append({
                "strategy": "Implement Redis cache",
                "cost_reduction": "30%",
                "implementation": "2 days"
            })
        
        # 2. Batch similar queries  
        if patterns['similar_queries'] > 100:
            optimizations.append({
                "strategy": "Query batching",
                "cost_reduction": "15%",
                "implementation": "1 day"
            })
        
        # 3. Reduce unnecessary metadata
        if patterns['unused_metadata_rate'] > 0.5:
            optimizations.append({
                "strategy": "Selective metadata retrieval",
                "cost_reduction": "10%",
                "implementation": "4 hours"
            })
        
        # 4. Optimize top_k values
        if patterns['avg_top_k'] > 50:
            optimizations.append({
                "strategy": "Dynamic top_k adjustment",
                "cost_reduction": "20%",
                "implementation": "1 day"
            })
        
        return CostReport(
            current_monthly_cost=self.calculate_current_cost(),
            projected_savings=sum(opt['cost_reduction'] for opt in optimizations),
            optimizations=optimizations,
            roi_timeline="2 months"
        )
```

### Index Lifecycle Management

```python
class IndexLifecycleManager:
    """Manage index lifecycle for cost optimization"""
    
    def __init__(self, pinecone_client):
        self.client = pinecone_client
        self.policies = {
            "hot": {"age": 0, "pod_type": "p2.x1"},
            "warm": {"age": 30, "pod_type": "p1.x1"},
            "cold": {"age": 90, "pod_type": "s1.x1"}
        }
    
    def apply_lifecycle_policies(self):
        """Apply lifecycle policies to all indexes"""
        
        for index_name in self.client.list_indexes():
            index = self.client.Index(index_name)
            stats = index.describe_index_stats()
            
            # Determine index age and usage
            age_days = self.get_index_age(index_name)
            usage_rate = self.get_usage_rate(index_name)
            
            # Apply appropriate policy
            if age_days > 90 and usage_rate < 0.1:
                self.transition_to_cold(index_name)
            elif age_days > 30 and usage_rate < 0.5:
                self.transition_to_warm(index_name)
            else:
                self.ensure_hot(index_name)
    
    def transition_to_cold(self, index_name: str):
        """Transition index to cold storage"""
        
        # 1. Create cold storage index
        cold_index_name = f"{index_name}_cold"
        self.client.create_index(
            name=cold_index_name,
            dimension=self.get_dimension(index_name),
            pod_type="s1.x1",
            pods=1
        )
        
        # 2. Migrate vectors in batches
        self.migrate_vectors(index_name, cold_index_name)
        
        # 3. Update routing
        self.update_query_routing(index_name, cold_index_name)
        
        # 4. Delete original index
        self.client.delete_index(index_name)
```

---

## Implementation Roadmap

### Phase 1: Foundation (Days 1-5)

```yaml
Day 1-2: Infrastructure Setup
  - Create Pinecone indexes with optimized configurations
  - Set up embedding pipeline with OpenAI/Cohere
  - Implement document processing pipeline
  - Create metadata extraction system

Day 3-4: Initial Data Load
  - Process and embed Executive Concierge Reports (48 documents)
  - Process and embed OSINT Collections (48 documents)
  - Process and embed Express Attack Briefs (144 documents)
  - Validate embeddings and metadata quality

Day 5: Testing and Validation
  - Test semantic search functionality
  - Validate metadata filtering
  - Performance benchmarking
  - Initial user acceptance testing
```

### Phase 2: Intelligence Enhancement (Days 6-10)

```yaml
Day 6-7: Advanced Search Implementation
  - Implement hybrid search engine
  - Create reranking system
  - Build contextual search features
  - Implement search analytics

Day 8-9: Neo4j Integration
  - Build unified query engine
  - Implement graph-enhanced embeddings
  - Create cross-system query patterns
  - Test integrated intelligence queries

Day 10: Account Manager Tools
  - Create AM-specific interfaces
  - Implement saved searches
  - Build morning briefing automation
  - Deploy beta version to AMs
```

### Phase 3: Automation & Real-time (Days 11-15)

```yaml
Day 11-12: Real-time Pipeline
  - Implement streaming intelligence ingestion
  - Create automated embedding pipeline
  - Build temporal decay system
  - Set up monitoring and alerting

Day 13-14: Automation Features
  - Email generation integration
  - EAB selection automation
  - Consultation prep automation
  - Proposal intelligence gathering

Day 15: Quality & Feedback
  - Implement feedback collection
  - Create quality metrics dashboard
  - Set up A/B testing framework
  - Deploy continuous improvement system
```

### Phase 4: Advanced Analytics (Days 16-20)

```yaml
Day 16-17: Predictive Analytics
  - Implement threat prediction models
  - Build vulnerability correlation engine
  - Create industry trend analyzer
  - Deploy M&A risk scoring

Day 18-19: Executive Dashboard
  - Create real-time analytics dashboard
  - Implement portfolio risk visualization
  - Build AM performance metrics
  - Deploy competitive intelligence tools

Day 20: Optimization & Launch
  - Performance optimization
  - Cost optimization implementation
  - Final testing and validation
  - Production deployment
```

### Success Criteria

```yaml
Technical Success:
  - 100% of artifacts indexed and searchable
  - <100ms average query latency
  - >95% search relevance score
  - 99.9% uptime

Business Success:
  - 50% reduction in research time for AMs
  - 3x improvement in email personalization
  - 25% increase in meeting acceptance rates
  - 100% AM adoption within 30 days

Strategic Success:
  - 10+ new opportunities identified monthly
  - 80% accuracy on threat predictions
  - Complete competitive intelligence coverage
  - Measurable improvement in win rates
```

---

## Conclusion

This Pinecone vector store architecture transforms Project Nightingale's static intelligence into a dynamic, AI-powered knowledge system. By combining:

- **Sophisticated embedding strategies** for different content types
- **Rich metadata schemas** enabling powerful filtering
- **Hybrid search patterns** balancing semantic and keyword search
- **Deep Neo4j integration** for graph-enhanced intelligence
- **Real-time update pipelines** for fresh intelligence
- **Cost-optimized infrastructure** for sustainable scaling

We create an intelligence platform that not only stores knowledge but actively generates insights, predicts threats, and empowers Account Managers to protect critical infrastructure.

The implementation focuses on immediate value delivery while building toward a future where every interaction is informed by the collective intelligence of the entire system.

**Next Steps**:
1. Review and approve architecture design
2. Provision Pinecone infrastructure
3. Begin Phase 1 implementation
4. Establish success metrics tracking

---

*"From 670 documents to infinite intelligence - powered by vectors, connected by graphs, delivered with precision."*