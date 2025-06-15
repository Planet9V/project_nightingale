# Project Nightingale: Complete Neo4j + Pinecone Schema Design
## Unified Intelligence Schema for GTM Excellence

**Document Classification**: Technical Schema Documentation  
**Created**: January 11, 2025  
**Version**: 1.0  
**Purpose**: Comprehensive schema reference for implementation

---

## 🗂️ Neo4j Graph Schema

### 📊 Node Types (Entities)

#### 1. **Prospect** (Core GTM Entity)
```cypher
(:Prospect {
  // Identifiers
  id: String,                    // "A-030734"
  name: String,                  // "Consumers Energy"
  
  // Classification
  industry: String,              // "Energy"
  sector: String,                // "Critical Infrastructure"
  sub_sector: String,            // "Electric & Gas Utility"
  
  // Business Intelligence
  revenue: Float,                // 6800000000
  employees: Integer,            // 8000
  headquarters: String,          // "Jackson, MI"
  
  // GTM Intelligence
  account_manager: String,       // "Jim Vranicar"
  engagement_stage: String,      // "QUALIFIED" | "CONTACTED" | "PROPOSAL" | "CLOSED"
  last_contact: DateTime,
  next_action: String,
  contract_value: Float,
  
  // Risk Profile
  risk_score: Float,             // 0.0 - 10.0
  vulnerability_count: Integer,
  exposure_level: String,        // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  
  // Threat Intelligence
  primary_threats: [String],     // ["BAUXITE", "VOLTZITE", "Supply Chain"]
  recent_incidents: [String],
  threat_alignment_score: Float,
  
  // Technology Profile
  technologies: [String],        // ["SCADA", "ICS", "Smart Grid", "Cloud"]
  ot_it_convergence: Boolean,
  internet_exposed_systems: Integer,
  
  // Compliance
  regulations: [String],         // ["NERC-CIP", "TSA", "EPA"]
  compliance_gaps: Integer,
  last_audit: DateTime,
  
  // Critical Services
  critical_services: [String],   // ["Power Generation", "Water Treatment"]
  population_served: Integer,
  economic_impact_daily: Float,
  
  // Temporal States (Quantum Entity)
  states: {
    current: {
      risk_score: Float,
      exposure_level: String,
      last_incident: DateTime
    },
    predicted_30d: {
      risk_score: Float,
      exposure_level: String,
      attack_probability: Float
    },
    predicted_90d: {
      risk_score: Float,
      exposure_level: String,
      attack_probability: Float
    },
    historical_trend: [Float]    // Risk scores over time
  }
})
```

#### 2. **ThreatActor** (Adversary Intelligence)
```cypher
(:ThreatActor {
  // Identifiers
  id: String,
  name: String,                  // "BAUXITE"
  aliases: [String],            // ["FrostyGoop", "IceBreaker"]
  
  // Classification
  type: String,                 // "Ransomware" | "APT" | "Hacktivist"
  origin: String,               // "Russia" | "China" | "Criminal"
  active_since: DateTime,
  
  // Behavioral Fingerprint
  behavioral_fingerprint: {
    // Temporal Patterns
    active_hours_utc: [Integer],     // [2, 3, 4, 14, 15, 16]
    active_days: [String],           // ["Mon", "Tue", "Thu"]
    campaign_duration_avg_days: Integer,
    time_between_campaigns_days: Integer,
    
    // Attack Preferences
    initial_access_methods: Map,     // {"phishing": 0.65, "supply_chain": 0.25}
    lateral_movement_tools: [String],
    persistence_techniques: [String],
    impact_methods: Map,             // {"ransomware": 0.8, "data_theft": 0.2}
    
    // Target Selection
    preferred_industries: [String],
    company_size_range: {min: Integer, max: Integer},
    geography_focus: [String],
    technology_targets: [String],    // ["SCADA", "ICS", "Windows"]
    
    // Operational Security
    opsec_score: Float,             // 0.0 - 10.0
    infrastructure_rotation_days: Integer,
    tool_reuse_rate: Float,
    detection_evasion_score: Float
  },
  
  // Capabilities
  capabilities: [String],         // ["ransomware", "ot_targeting", "supply_chain"]
  sophistication_level: String,  // "HIGH" | "MEDIUM" | "LOW"
  
  // Activity Tracking
  last_observed: DateTime,
  total_victims: Integer,
  successful_attacks: Integer,
  average_ransom_demand: Float,
  
  // Intelligence Sources
  intelligence_sources: [String], // ["CISA", "FBI", "Dragos", "Mandiant"]
  confidence_level: Float
})
```

#### 3. **ExpressAttackBrief** (EAB GTM Artifact)
```cypher
(:ExpressAttackBrief {
  // Identifiers
  id: String,                    // "EAB-030734-001"
  prospect_id: String,
  creation_date: DateTime,
  
  // Attack Scenario
  threat_actor: String,
  attack_scenario: String,
  likelihood: Float,             // 0.0 - 1.0
  
  // MITRE ATT&CK Mapping
  mitre_tactics: [String],       // ["Initial Access", "Execution", "Impact"]
  mitre_techniques: [String],    // ["T1566", "T1059", "T1486"]
  mitre_subtechniques: [String],
  
  // Attack Pattern
  attack_pattern: {
    initial_access: String,
    privilege_escalation: String,
    lateral_movement: String,
    collection: String,
    exfiltration: String,
    impact: String
  },
  
  // Business Impact
  potential_impact: {
    financial_loss: Float,
    downtime_hours: Integer,
    data_loss_gb: Float,
    reputation_score: Float,
    regulatory_fines: Float
  },
  
  // GTM Value
  talking_points: [String],
  competitor_incidents: [String],
  quantified_risk: Float,
  
  // Defense Recommendations
  quick_wins: [String],
  strategic_improvements: [String],
  tri_partner_solution: {
    ncc_otce: String,
    dragos: String,
    adelard: String
  },
  
  // Effectiveness Metrics
  similar_attacks_prevented: Integer,
  detection_confidence: Float
})
```

#### 4. **Vulnerability** (Security Weakness)
```cypher
(:Vulnerability {
  // Identifiers
  cve_id: String,                // "CVE-2024-1234"
  name: String,
  
  // Severity Metrics
  cvss_score: Float,            // 0.0 - 10.0
  cvss_vector: String,
  severity: String,             // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  
  // Exploitation Intelligence
  exploitability: {
    exploit_available: Boolean,
    exploit_maturity: String,   // "WEAPONIZED" | "POC" | "THEORETICAL"
    in_the_wild: Boolean,
    first_seen_wild: DateTime,
    exploitation_velocity: Float // Days from disclosure to exploitation
  },
  
  // Technical Details
  vulnerability_type: String,   // "RCE" | "SQLi" | "XSS" | "PrivEsc"
  affected_products: [String],
  affected_versions: [String],
  
  // Remediation
  patch_available: Boolean,
  patch_release_date: DateTime,
  workaround_available: Boolean,
  mitigation_steps: [String],
  
  // Intelligence
  cisa_kev: Boolean,           // In Known Exploited Vulnerabilities
  threat_actors_using: [String],
  targeted_industries: [String],
  
  // Impact Metrics
  systems_affected_global: Integer,
  criticality_score: Float
})
```

#### 5. **Technology** (Systems and Software)
```cypher
(:Technology {
  // Identifiers
  id: String,
  name: String,                 // "Schneider Electric Modicon M580"
  vendor: String,
  category: String,            // "SCADA" | "PLC" | "HMI" | "Firewall"
  
  // Version Information
  version: String,
  firmware_version: String,
  end_of_life: DateTime,
  
  // Deployment Context
  environment: String,         // "OT" | "IT" | "Cloud" | "Hybrid"
  criticality: String,        // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  
  // Security Profile
  vulnerability_count: Integer,
  patch_compliance: Float,     // 0.0 - 1.0
  security_features: [String],
  
  // Configuration
  internet_exposed: Boolean,
  default_credentials: Boolean,
  encryption_enabled: Boolean,
  
  // Operational Impact
  processes_supported: [String],
  downtime_impact_hourly: Float,
  replacement_cost: Float,
  replacement_time_days: Integer
})
```

#### 6. **AccountManager** (Sales Intelligence)
```cypher
(:AccountManager {
  // Identifiers
  id: String,
  name: String,                // "Jim Vranicar"
  email: String,
  
  // Role Information
  title: String,              // "Energy Sector Lead"
  region: String,
  sectors: [String],          // ["Energy", "Transportation"]
  
  // Performance Metrics
  total_prospects: Integer,
  active_prospects: Integer,
  conversion_rate: Float,
  average_deal_size: Float,
  total_revenue: Float,
  
  // Expertise
  specializations: [String],   // ["NERC-CIP", "Smart Grid", "OT Security"]
  certifications: [String],
  years_experience: Integer,
  
  // Success Patterns
  proven_approaches: [String],
  preferred_themes: [String],
  best_performing_content: [String],
  
  // Activity Tracking
  last_activity: DateTime,
  meetings_this_month: Integer,
  proposals_outstanding: Integer
})
```

#### 7. **ConciergeReport** (Executive Intelligence)
```cypher
(:ConciergeReport {
  // Identifiers
  id: String,
  prospect_id: String,
  version: String,
  creation_date: DateTime,
  
  // Report Content
  executive_summary: String,
  threat_landscape: String,
  vulnerability_assessment: String,
  
  // Risk Analysis
  overall_risk_score: Float,
  risk_factors: [String],
  risk_trajectory: String,     // "INCREASING" | "STABLE" | "DECREASING"
  
  // Quantified Impact
  potential_losses: {
    ransomware: Float,
    operational_downtime: Float,
    regulatory_fines: Float,
    reputation_damage: Float,
    total_exposure: Float
  },
  
  // Recommendations
  immediate_actions: [String],
  strategic_initiatives: [String],
  investment_required: Float,
  roi_timeline_months: Integer,
  
  // Competitive Intelligence
  peer_comparisons: [String],
  industry_benchmarks: Map,
  
  // Success Metrics
  kpis_defined: [String],
  success_criteria: [String]
})
```

#### 8. **Supplier** (Supply Chain Node)
```cypher
(:Supplier {
  // Identifiers
  id: String,
  name: String,
  
  // Classification
  tier: Integer,              // 1, 2, 3, 4...
  category: String,          // "Hardware" | "Software" | "Service"
  criticality: String,
  
  // Risk Profile
  security_maturity: Integer, // 1-5
  last_assessment: DateTime,
  known_breaches: Integer,
  
  // Operational Details
  lead_time_days: Integer,
  single_source: Boolean,
  alternatives_count: Integer,
  
  // Geographic Risk
  headquarters_country: String,
  manufacturing_countries: [String],
  geopolitical_risk: Float
})
```

### 🔗 Relationship Types

#### 1. **ACTIVELY_TARGETING**
```cypher
(:ThreatActor)-[:ACTIVELY_TARGETING {
  confidence: Float,           // 0.0 - 1.0
  evidence: [String],
  first_observed: DateTime,
  last_activity: DateTime,
  predicted_attack_window: String,
  attack_stage: String        // "Reconnaissance" | "Weaponization" | "Delivery"
}]->(:Prospect)
```

#### 2. **HAS_VULNERABILITY**
```cypher
(:Technology)-[:HAS_VULNERABILITY {
  discovered: DateTime,
  severity_context: String,    // Severity in this specific context
  exploitability_local: Float,
  patch_status: String,       // "Available" | "Testing" | "Deployed" | "None"
  compensating_controls: [String]
}]->(:Vulnerability)
```

#### 3. **USES_TECHNOLOGY**
```cypher
(:Prospect)-[:USES_TECHNOLOGY {
  deployment_date: DateTime,
  environment: String,
  instance_count: Integer,
  criticality: String,
  internet_exposed: Boolean,
  last_updated: DateTime,
  lifecycle_stage: String    // "Production" | "Development" | "Decommission"
}]->(:Technology)
```

#### 4. **EXPLOITS**
```cypher
(:ThreatActor)-[:EXPLOITS {
  frequency: Float,          // How often they use this
  success_rate: Float,
  first_use: DateTime,
  last_use: DateTime,
  variants: [String]        // Different exploitation methods
}]->(:Vulnerability)
```

#### 5. **DEPENDS_ON**
```cypher
(:Prospect)-[:DEPENDS_ON {
  dependency_type: String,   // "Critical" | "Important" | "Standard"
  contract_value: Float,
  contract_expiry: DateTime,
  switching_cost: Float,
  switching_time_days: Integer
}]->(:Supplier)
```

#### 6. **MANAGES**
```cypher
(:AccountManager)-[:MANAGES {
  assigned_date: DateTime,
  engagement_level: String,  // "High" | "Medium" | "Low"
  last_contact: DateTime,
  next_action: String,
  relationship_score: Float
}]->(:Prospect)
```

#### 7. **CONVERTED**
```cypher
(:AccountManager)-[:CONVERTED {
  close_date: DateTime,
  contract_value: Float,
  solution_sold: String,
  sales_cycle_days: Integer,
  key_factors: [String],
  themes_used: [String]
}]->(:Prospect)
```

#### 8. **SIMILAR_TO**
```cypher
(:Prospect)-[:SIMILAR_TO {
  similarity_score: Float,
  common_factors: [String],
  shared_vulnerabilities: Integer,
  shared_threats: [String]
}]->(:Prospect)
```

---

## 📊 Pinecone Vector Schema

### Vector Metadata Structure

```python
{
    # Document Identification
    "artifact_id": str,              # Unique document ID
    "artifact_type": str,            # "concierge_report" | "eab" | "osint" | "playbook"
    "artifact_path": str,            # File system path
    "chunk_index": int,              # Position in document
    "chunk_text": str,               # First 1000 chars of chunk
    
    # Prospect Intelligence
    "prospect_id": str,              # "A-030734"
    "company_name": str,             # "Consumers Energy"
    "industry": str,                 # "Energy"
    "sector": str,                   # "Critical Infrastructure"
    "account_manager": str,          # "Jim Vranicar"
    
    # Threat Intelligence
    "threat_actors": List[str],      # ["BAUXITE", "VOLTZITE"]
    "threat_campaigns": List[str],   # Active campaigns mentioned
    "ttps": List[str],              # Tactics, Techniques, Procedures
    "indicators": List[str],         # IOCs found in text
    
    # Vulnerability Intelligence
    "vulnerabilities": List[str],    # ["CVE-2024-1234", "CVE-2024-5678"]
    "vulnerable_products": List[str],
    "exploit_available": bool,
    "patch_status": str,
    
    # Technology Stack
    "technologies": List[str],       # ["SCADA", "Schneider", "Windows Server"]
    "vendors": List[str],
    "versions": List[str],
    "environments": List[str],       # ["OT", "IT", "Cloud"]
    
    # Compliance & Regulations
    "regulations": List[str],        # ["NERC-CIP", "TSA"]
    "compliance_gaps": List[str],
    "audit_findings": List[str],
    
    # Business Impact
    "financial_impact": float,       # Extracted dollar amounts
    "downtime_risk_hours": int,
    "affected_population": int,
    "critical_services": List[str],
    
    # Sales Intelligence
    "themes": List[str],            # ["ransomware", "supply_chain", "m&a"]
    "value_propositions": List[str],
    "objections": List[str],
    "decision_makers": List[str],   # Titles mentioned
    
    # MITRE ATT&CK
    "mitre_tactics": List[str],
    "mitre_techniques": List[str],
    "mitre_subtechniques": List[str],
    "kill_chain_phase": str,
    
    # Temporal Intelligence
    "created_date": str,            # ISO format
    "last_updated": str,
    "intelligence_age_days": int,
    "expiry_date": str,            # When intelligence becomes stale
    
    # Search Optimization
    "keywords": List[str],          # Extracted key terms
    "entities": List[str],          # Named entities (people, places, orgs)
    "acronyms": List[str],          # Industry acronyms found
    "sentiment": float,             # -1.0 to 1.0
    
    # Quality Metrics
    "source_credibility": float,    # 0.0 - 1.0
    "information_completeness": float,
    "actionability_score": float,
    
    # Relationship Hints (for Neo4j correlation)
    "related_prospects": List[str],
    "related_suppliers": List[str],
    "related_incidents": List[str],
    
    # Custom Tags
    "tags": List[str],              # User-defined tags
    "categories": List[str],        # Hierarchical categorization
    "priority": str,                # "HIGH" | "MEDIUM" | "LOW"
}
```

### Embedding Dimensions

```python
# Embedding Configuration
EMBEDDING_MODEL = "text-embedding-3-large"
EMBEDDING_DIMENSIONS = 1024

# Semantic Spaces (different embedding strategies)
EMBEDDING_TYPES = {
    "general": 1024,        # General purpose embeddings
    "technical": 512,       # Technical details focus
    "business": 512,        # Business impact focus
    "threat": 768,          # Threat intelligence focus
}
```

### Index Configuration

```python
# Pinecone Index Settings
INDEX_CONFIG = {
    "name": "nightingale",
    "dimension": 1024,
    "metric": "cosine",
    "pods": 1,
    "replicas": 1,
    "pod_type": "p1.x1",
    
    # Metadata indexing
    "metadata_config": {
        "indexed": [
            "artifact_type",
            "prospect_id",
            "company_name",
            "industry",
            "threat_actors",
            "themes",
            "created_date",
            "priority"
        ]
    }
}
```

---

## 🔄 Cross-Database Relationships

### Neo4j → Pinecone Linking
```python
# Every Neo4j node can reference Pinecone vectors
neo4j_node["vector_ids"] = ["vec_001", "vec_002", "vec_003"]

# Every Pinecone vector references Neo4j nodes
pinecone_metadata["neo4j_node_id"] = "node_12345"
pinecone_metadata["neo4j_node_type"] = "Prospect"
```

### Unified Query Example
```python
# Step 1: Semantic search in Pinecone
vector_results = pinecone.query(
    vector=embed("ransomware attack on energy sector"),
    filter={"industry": "Energy"},
    top_k=10
)

# Step 2: Get Neo4j node IDs from results
node_ids = [r.metadata["neo4j_node_id"] for r in vector_results]

# Step 3: Graph traversal in Neo4j
graph_results = neo4j.query("""
    MATCH (p:Prospect)
    WHERE p.id IN $node_ids
    MATCH (p)-[:USES_TECHNOLOGY]->(t:Technology)
    MATCH (t)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    MATCH (ta:ThreatActor)-[:EXPLOITS]->(v)
    RETURN p, t, v, ta
""", node_ids=node_ids)
```

---

## 📈 Schema Evolution Strategy

### Version Control
- Schema versions tracked in both databases
- Backward compatibility for 2 major versions
- Migration scripts for schema updates

### Extensibility Points
- Custom node labels for new entity types
- Dynamic properties for client-specific data
- Relationship properties can be extended
- Vector metadata can include custom fields

### Performance Optimization
- Neo4j: Indexes on id, name, industry, risk_score
- Pinecone: Metadata filtering on key fields
- Batch processing for large imports
- Caching layer for frequent queries

---

This schema design provides a comprehensive foundation for Project Nightingale's intelligence system, enabling powerful multi-hop analysis, semantic search, and predictive threat intelligence.