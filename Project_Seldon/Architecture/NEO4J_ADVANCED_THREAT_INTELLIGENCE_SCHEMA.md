# Project Nightingale: Advanced Threat Intelligence Graph Schema
## Comprehensive Entity Model for Predictive Risk Analysis

**Document Classification**: Advanced Schema Architecture  
**Created**: January 11, 2025  
**Version**: 2.0  
**Purpose**: Enable "Now, Next, or Never" prioritization through real-world threat intelligence

---

## 🎯 Schema Philosophy

This schema is designed to answer the critical question: **"What should our clients do NOW, NEXT, or NEVER?"** based on:
- **Real incidents**, not theoretical risks
- **Active exploitation**, not just vulnerabilities
- **Actual threat actor behavior**, not assumptions
- **Measured impact**, not estimated losses
- **Proven defenses**, not vendor promises

---

## 🏗️ Core Entity Types

### 1. **Person** (Individuals in the Ecosystem)
```cypher
(:Person {
  // Identifiers
  id: String,
  full_name: String,
  aliases: [String],
  
  // Professional Identity
  current_title: String,
  current_organization: String,
  previous_roles: [{
    title: String,
    organization: String,
    start_date: DateTime,
    end_date: DateTime
  }],
  
  // Expertise & Influence
  expertise_areas: [String],      // ["ICS Security", "Ransomware", "SCADA"]
  certifications: [String],
  publications: [String],
  speaking_engagements: Integer,
  influence_score: Float,         // 0-10 industry influence
  
  // Contact & Social
  email: String,
  linkedin: String,
  twitter: String,
  github: String,
  
  // Role Classification
  role_type: String,             // "Executive" | "Technical" | "Researcher" | "ThreatActor"
  security_clearance: String,
  
  // For Threat Actors
  threat_actor_profile: {
    known_aliases: [String],
    attributed_attacks: [String],
    skill_level: String,         // "Elite" | "Advanced" | "Intermediate"
    motivations: [String]        // ["Financial", "Espionage", "Hacktivism"]
  }
})
```

### 2. **Organization** (All Types of Organizations)
```cypher
(:Organization {
  // Identifiers
  id: String,
  name: String,
  aliases: [String],
  ticker_symbol: String,
  
  // Classification
  type: String,                  // "Company" | "Government" | "Criminal" | "APT"
  sub_type: String,             // "Utility" | "Manufacturer" | "Agency" | "Ransomware"
  industry: String,
  sector: String,
  
  // Profile
  headquarters_location: String,
  operating_countries: [String],
  employee_count: Integer,
  revenue: Float,
  founded_year: Integer,
  
  // For Companies
  company_profile: {
    critical_infrastructure: Boolean,
    publicly_traded: Boolean,
    fortune_rank: Integer,
    cyber_insurance_coverage: Float,
    security_budget: Float,
    ciso_reporting_level: String  // "CEO" | "CTO" | "CIO"
  },
  
  // For Threat Groups
  threat_group_profile: {
    first_observed: DateTime,
    last_active: DateTime,
    victim_count: Integer,
    total_demanded: Float,
    total_paid: Float,
    average_dwell_time_days: Integer,
    preferred_sectors: [String],
    affiliate_model: Boolean
  },
  
  // For Government Entities
  government_profile: {
    level: String,               // "Federal" | "State" | "Local"
    regulatory_authority: Boolean,
    enforcement_actions: Integer,
    published_advisories: Integer
  }
})
```

### 3. **Place** (Geographic Entities)
```cypher
(:Place {
  // Identifiers
  id: String,
  name: String,
  place_type: String,           // "Country" | "State" | "City" | "Facility"
  
  // Geographic Data
  country_code: String,
  state_province: String,
  city: String,
  latitude: Float,
  longitude: Float,
  timezone: String,
  
  // Risk Factors
  geopolitical_risk: Float,     // 0-10
  natural_disaster_risk: Float,
  infrastructure_maturity: Float,
  cyber_maturity_index: Float,
  
  // Critical Infrastructure
  critical_facilities: [{
    name: String,
    type: String,               // "Power Plant" | "Water Treatment" | "Hospital"
    capacity: String,
    population_served: Integer
  }],
  
  // Regulatory Environment
  data_residency_required: Boolean,
  privacy_laws: [String],
  breach_notification_hours: Integer,
  
  // Threat Landscape
  active_threat_groups: [String],
  recent_incidents_count: Integer,
  cybercrime_index: Float
})
```

### 4. **Incident** (Actual Security Incidents)
```cypher
(:Incident {
  // Identifiers
  id: String,
  name: String,                 // "Colonial Pipeline Ransomware"
  incident_date: DateTime,
  discovery_date: DateTime,
  
  // Classification
  type: String,                 // "Ransomware" | "DataBreach" | "Sabotage" | "Espionage"
  severity: String,             // "Critical" | "High" | "Medium" | "Low"
  attribution_confidence: Float,
  
  // Timeline
  timeline: [{
    timestamp: DateTime,
    event: String,
    source: String
  }],
  initial_access_date: DateTime,
  containment_date: DateTime,
  recovery_date: DateTime,
  total_duration_days: Integer,
  
  // Impact Assessment
  impact: {
    financial_loss: Float,
    ransom_demanded: Float,
    ransom_paid: Float,
    downtime_hours: Integer,
    data_exfiltrated_gb: Float,
    records_compromised: Integer,
    systems_encrypted: Integer,
    
    // Operational Impact
    production_stopped: Boolean,
    services_disrupted: [String],
    customers_affected: Integer,
    
    // Human Impact
    injuries: Integer,
    fatalities: Integer,
    evacuations: Integer,
    
    // Cascading Effects
    supply_chain_disrupted: Boolean,
    downstream_companies_affected: Integer,
    economic_impact_regional: Float
  },
  
  // Technical Details
  attack_vectors: [String],
  vulnerabilities_exploited: [String],
  tools_used: [String],
  malware_families: [String],
  c2_infrastructure: [String],
  
  // Response & Recovery
  incident_response: {
    response_time_hours: Float,
    responder_organizations: [String],
    law_enforcement_involved: Boolean,
    recovery_time_days: Integer,
    total_cost: Float
  },
  
  // Lessons Learned
  root_causes: [String],
  security_failures: [String],
  successful_defenses: [String],
  recommendations: [String],
  
  // Intelligence Value
  indicators_extracted: Integer,
  ttps_documented: Boolean,
  public_reporting: Boolean,
  intelligence_shared: Boolean
})
```

### 5. **Vulnerability** (Enhanced)
```cypher
(:Vulnerability {
  // Identifiers
  id: String,
  cve_id: String,
  name: String,
  aliases: [String],
  
  // Discovery & Disclosure
  discovery_date: DateTime,
  disclosure_date: DateTime,
  discoverer: String,
  disclosure_type: String,      // "Responsible" | "Zero-day" | "Full"
  
  // Technical Classification
  vulnerability_type: String,    // "RCE" | "SQLi" | "BufferOverflow" | "LogicFlaw"
  attack_vector: String,        // "Network" | "Local" | "Physical"
  attack_complexity: String,    // "Low" | "High"
  privileges_required: String,  // "None" | "Low" | "High"
  user_interaction: String,     // "None" | "Required"
  
  // Scoring
  cvss_v3_score: Float,
  cvss_v3_vector: String,
  epss_score: Float,           // Exploit Prediction Scoring System
  vep_score: Float,            // Vendor Priority Score
  
  // Real-World Exploitation
  exploitation_status: {
    in_the_wild: Boolean,
    first_seen_wild: DateTime,
    exploitation_volume: String, // "Widespread" | "Limited" | "Targeted"
    exploit_kit_integration: Boolean,
    commercial_exploit: Boolean,
    exploit_price_usd: Float,
    
    // Exploitation Telemetry
    honeypot_hits_daily: Integer,
    scanning_attempts_daily: Integer,
    successful_compromises: Integer
  },
  
  // Affected Systems
  affected_products: [{
    vendor: String,
    product: String,
    versions: [String],
    end_of_life: Boolean,
    installations_global: Integer,
    patch_adoption_rate: Float
  }],
  
  // Threat Intelligence
  threat_actors_using: [String],
  malware_families_using: [String],
  targeted_sectors: [String],
  targeted_countries: [String],
  
  // Remediation
  patch_available: Boolean,
  patch_release_date: DateTime,
  patch_adoption_rate: Float,
  workaround_available: Boolean,
  workaround_effectiveness: Float,
  virtual_patch_available: Boolean,
  
  // Compliance & Regulatory
  cisa_kev: Boolean,
  regulatory_attention: Boolean,
  compliance_deadline: DateTime,
  
  // Impact Predictions
  predicted_impact: {
    likelihood_of_exploit_30d: Float,
    potential_victims: Integer,
    estimated_damage_usd: Float
  }
})
```

### 6. **Exploit** (Actual Exploit Code/Techniques)
```cypher
(:Exploit {
  // Identifiers
  id: String,
  name: String,
  exploit_db_id: String,
  
  // Classification
  type: String,                // "PoC" | "Weaponized" | "Commercial"
  reliability: String,         // "High" | "Medium" | "Low"
  
  // Technical Details
  targeted_vulnerability: String,
  targeted_products: [String],
  targeted_versions: [String],
  platform: String,           // "Windows" | "Linux" | "Firmware"
  architecture: String,       // "x86" | "x64" | "ARM"
  
  // Capabilities
  capabilities: {
    remote_execution: Boolean,
    privilege_escalation: Boolean,
    sandbox_escape: Boolean,
    persistence: Boolean,
    stealth_rating: Float
  },
  
  // Availability
  public_availability: Boolean,
  publication_date: DateTime,
  source_code_available: Boolean,
  github_repository: String,
  underground_price_usd: Float,
  
  // Usage Telemetry
  usage_observed: Boolean,
  first_seen_wild: DateTime,
  detection_rate: Float,
  success_rate: Float,
  
  // Integration
  exploit_kits_integrated: [String],
  malware_integrated: [String],
  automation_level: String    // "Manual" | "Semi-Auto" | "Fully-Auto"
})
```

### 7. **TechnologyStack** (Complete Technology Profile)
```cypher
(:TechnologyStack {
  // Identifiers
  id: String,
  organization_id: String,
  last_updated: DateTime,
  
  // Stack Layers
  infrastructure: {
    cloud_providers: [String],
    on_premise_percentage: Float,
    data_centers: [String],
    edge_locations: Integer
  },
  
  operating_systems: [{
    name: String,
    version: String,
    count: Integer,
    eol_date: DateTime,
    patch_level: String
  }],
  
  applications: [{
    name: String,
    vendor: String,
    version: String,
    criticality: String,
    internet_facing: Boolean,
    authentication_type: String
  }],
  
  ot_systems: [{
    type: String,              // "SCADA" | "DCS" | "PLC" | "HMI"
    vendor: String,
    model: String,
    firmware_version: String,
    network_segregated: Boolean,
    last_updated: DateTime
  }],
  
  security_tools: [{
    category: String,          // "EDR" | "SIEM" | "Firewall" | "IDS"
    vendor: String,
    product: String,
    coverage_percentage: Float,
    properly_configured: Boolean
  }],
  
  // Technology Debt
  technical_debt: {
    legacy_systems_count: Integer,
    unsupported_systems_count: Integer,
    unpatched_criticals: Integer,
    security_exceptions: Integer,
    compensating_controls: [String]
  },
  
  // Integration Complexity
  integration_points: Integer,
  api_endpoints_exposed: Integer,
  third_party_connections: Integer,
  data_flows_documented: Boolean
})
```

### 8. **ComplianceFramework** (Regulatory Requirements)
```cypher
(:ComplianceFramework {
  // Identifiers
  id: String,
  name: String,               // "NERC-CIP" | "TSA" | "GDPR"
  version: String,
  
  // Metadata
  issuing_body: String,
  jurisdiction: String,
  effective_date: DateTime,
  last_updated: DateTime,
  
  // Scope
  applicable_sectors: [String],
  applicable_entities: [String],
  geography: [String],
  
  // Requirements
  requirements: [{
    id: String,
    category: String,
    description: String,
    criticality: String,
    implementation_cost: String, // "Low" | "Medium" | "High"
    typical_time_months: Integer
  }],
  
  // Enforcement
  enforcement: {
    regulatory_body: String,
    audit_frequency: String,
    self_assessment_required: Boolean,
    third_party_audit_required: Boolean,
    
    penalties: {
      max_fine_usd: Float,
      daily_fine_usd: Float,
      criminal_liability: Boolean,
      license_revocation: Boolean
    }
  },
  
  // Cybersecurity Focus
  security_controls_required: Integer,
  incident_reporting_required: Boolean,
  incident_reporting_timeline_hours: Integer,
  vulnerability_management_required: Boolean,
  supply_chain_requirements: Boolean,
  
  // Maturity Levels
  maturity_model: Boolean,
  maturity_levels: [String],
  certification_available: Boolean
})
```

### 9. **Concept** (Threat Concepts & Methodologies)
```cypher
(:Concept {
  // Identifiers
  id: String,
  name: String,               // "Living off the Land" | "Supply Chain Attack"
  category: String,           // "TTP" | "Attack Pattern" | "Defense Strategy"
  
  // Description
  definition: String,
  first_documented: DateTime,
  evolution_timeline: [{
    date: DateTime,
    development: String
  }],
  
  // Relationships
  parent_concepts: [String],
  child_concepts: [String],
  related_concepts: [String],
  
  // Real-World Usage
  incidents_using: [String],
  threat_actors_using: [String],
  effectiveness_rating: Float,
  detection_difficulty: Float,
  
  // Defensive Measures
  detection_methods: [String],
  prevention_methods: [String],
  mitigation_strategies: [String],
  
  // Intelligence Value
  predictive_indicator: Boolean,
  early_warning_sign: Boolean,
  maturity_indicator: String
})
```

### 10. **Report** (Intelligence Reports)
```cypher
(:Report {
  // Identifiers
  id: String,
  title: String,
  report_type: String,        // "Incident" | "Threat" | "Vulnerability" | "Strategic"
  
  // Metadata
  authors: [String],
  organization: String,
  publication_date: DateTime,
  classification: String,     // "Public" | "TLP:White" | "TLP:Green" | "TLP:Amber"
  
  // Content Summary
  executive_summary: String,
  key_findings: [String],
  recommendations: [String],
  
  // Intelligence Value
  incidents_analyzed: [String],
  new_iocs: Integer,
  new_ttps: Integer,
  predictions_made: [{
    prediction: String,
    confidence: Float,
    timeframe: String
  }],
  
  // Validation
  peer_reviewed: Boolean,
  citations_count: Integer,
  accuracy_score: Float,      // Based on prediction outcomes
  
  // Usage Metrics
  downloads: Integer,
  citations_by_others: Integer,
  implementation_reported: Integer
})
```

### 11. **Expert** (Subject Matter Experts)
```cypher
(:Expert {
  // Identifiers
  id: String,
  person_id: String,          // Links to Person entity
  
  // Expertise Profile
  primary_expertise: [String],
  secondary_expertise: [String],
  years_experience: Integer,
  
  // Credibility Metrics
  publications_count: Integer,
  citations_count: Integer,
  correct_predictions: Integer,
  incorrect_predictions: Integer,
  accuracy_rate: Float,
  
  // Thought Leadership
  keynote_speeches: Integer,
  advisory_positions: [String],
  media_appearances: Integer,
  social_media_followers: Integer,
  
  // Availability
  consulting_available: Boolean,
  speaking_available: Boolean,
  typical_fee_range: String,
  
  // Track Record
  major_discoveries: [String],
  incident_responses_led: Integer,
  frameworks_created: [String]
})
```

### 12. **Government** (Government Entities)
```cypher
(:Government {
  // Identifiers
  id: String,
  name: String,
  country_code: String,
  
  // Structure
  level: String,              // "National" | "State" | "Local"
  type: String,              // "Executive" | "Legislative" | "Regulatory"
  parent_entity: String,
  
  // Cybersecurity Role
  cyber_authority: Boolean,
  regulatory_power: Boolean,
  law_enforcement: Boolean,
  intelligence_sharing: Boolean,
  
  // Capabilities
  cert_team: Boolean,         // Has CERT/CSIRT
  threat_intelligence_unit: Boolean,
  offensive_capabilities: Boolean,
  
  // Activity Metrics
  advisories_published: Integer,
  regulations_enacted: Integer,
  enforcement_actions: Integer,
  sanctions_imposed: Integer,
  
  // International Cooperation
  treaties_signed: [String],
  information_sharing_agreements: [String],
  joint_operations: Integer
})
```

---

## 🔗 Critical Relationship Types

### Threat Intelligence Relationships

#### **ATTRIBUTED_TO**
```cypher
(:Incident)-[:ATTRIBUTED_TO {
  confidence: Float,          // 0.0-1.0
  attribution_method: String, // "TTP Analysis" | "Infrastructure" | "Malware"
  evidence: [String],
  dissenting_opinions: [String],
  government_attribution: Boolean
}]->(:Organization|:Person)
```

#### **EXPLOITED_IN**
```cypher
(:Vulnerability)-[:EXPLOITED_IN {
  exploitation_method: String,
  success_rate: Float,
  first_observed: DateTime,
  detection_bypass: [String],
  patches_bypassed: Boolean
}]->(:Incident)
```

#### **PRECEDED_BY**
```cypher
(:Incident)-[:PRECEDED_BY {
  time_delta_days: Integer,
  causal_relationship: Boolean,
  shared_infrastructure: Boolean,
  lessons_not_learned: [String]
}]->(:Incident)
```

### Risk Assessment Relationships

#### **INCREASES_RISK_FOR**
```cypher
(:Vulnerability)-[:INCREASES_RISK_FOR {
  risk_multiplier: Float,
  time_window_days: Integer,
  exploitation_likelihood: Float,
  business_impact: String
}]->(:Organization)
```

#### **MITIGATES**
```cypher
(:Technology|:ComplianceFramework)-[:MITIGATES {
  effectiveness: Float,       // 0.0-1.0
  coverage: Float,           // Percentage of risk covered
  implementation_time_days: Integer,
  implementation_cost: Float,
  maintenance_burden: String  // "Low" | "Medium" | "High"
}]->(:Vulnerability|:Concept)
```

### Supply Chain Relationships

#### **SUPPLIES_TO**
```cypher
(:Organization)-[:SUPPLIES_TO {
  components: [String],
  criticality: String,
  contract_value: Float,
  sla_availability: Float,
  alternate_suppliers: Integer,
  switching_time_days: Integer
}]->(:Organization)
```

#### **CASCADES_TO**
```cypher
(:Incident)-[:CASCADES_TO {
  impact_delay_hours: Integer,
  impact_severity: Float,
  mitigation_possible: Boolean,
  notification_sent: DateTime
}]->(:Organization)
```

### Expertise Relationships

#### **RESPONDED_TO**
```cypher
(:Expert|:Organization)-[:RESPONDED_TO {
  response_time_hours: Float,
  role: String,              // "Lead" | "Advisor" | "Analyst"
  effectiveness: String,
  cost: Float,
  lessons_documented: Boolean
}]->(:Incident)
```

#### **PREDICTED**
```cypher
(:Expert|:Report)-[:PREDICTED {
  prediction: String,
  confidence: Float,
  timeframe: String,
  accuracy: Float,           // Measured after the fact
  factors_considered: [String]
}]->(:Incident|:Vulnerability)
```

---

## 🎯 "Now, Next, or Never" Decision Engine

### Priority Calculation Query
```cypher
// Calculate NOW priorities (action within 24-48 hours)
MATCH (o:Organization {id: $org_id})
MATCH (v:Vulnerability)-[:INCREASES_RISK_FOR]->(o)
WHERE v.exploitation_status.in_the_wild = true
  AND v.patch_available = true
  AND NOT EXISTS((o)-[:PATCHED]->(v))
  
MATCH (ta:Organization {type: "Criminal"})-[:EXPLOITS]->(v)
WHERE ta.threat_group_profile.last_active > datetime() - duration({days: 7})

MATCH (similar:Incident)-[:EXPLOITED_IN]-(v)
WHERE similar.incident_date > datetime() - duration({days: 30})

WITH o, v, ta, collect(similar) as recent_incidents,
     v.exploitation_status.exploitation_volume as volume,
     v.epss_score as exploit_probability

RETURN 
  v.cve_id as vulnerability,
  v.cvss_v3_score as severity,
  exploit_probability,
  volume as exploitation_volume,
  size(recent_incidents) as recent_incidents_count,
  avg([i IN recent_incidents | i.impact.financial_loss]) as avg_impact,
  collect(DISTINCT ta.name) as active_threat_actors,
  'NOW' as priority,
  'Patch within 24 hours - Active exploitation ongoing' as action
ORDER BY exploit_probability * severity DESC

UNION

// Calculate NEXT priorities (action within 7-30 days)
MATCH (o:Organization {id: $org_id})
MATCH (v:Vulnerability)-[:INCREASES_RISK_FOR]->(o)
WHERE v.exploitation_status.in_the_wild = false
  AND v.epss_score > 0.3
  AND (v.exploit_available = true OR v.exploitation_status.exploit_kit_integration = true)
  
// ... similar pattern for NEXT

UNION

// Calculate NEVER priorities (deprioritize)
MATCH (o:Organization {id: $org_id})
MATCH (v:Vulnerability)-[:INCREASES_RISK_FOR]->(o)
WHERE v.exploitation_status.in_the_wild = false
  AND v.epss_score < 0.1
  AND NOT EXISTS((:Incident)-[:EXPLOITED_IN]-(v))
  AND v.disclosure_date < datetime() - duration({years: 2})
  
// ... pattern for NEVER
```

### Predictive Risk Score
```cypher
// Calculate 30-day risk prediction
MATCH (o:Organization {id: $org_id})

// Factor 1: Direct targeting
OPTIONAL MATCH (ta:Organization {type: "Criminal"})-[t:TARGETS]->(o)
WHERE t.last_activity > datetime() - duration({days: 90})
WITH o, collect(ta) as direct_threats

// Factor 2: Industry targeting
MATCH (peer:Organization {industry: o.industry})
MATCH (incident:Incident)-[:AFFECTED]->(peer)
WHERE incident.incident_date > datetime() - duration({days: 180})
WITH o, direct_threats, collect(DISTINCT incident) as industry_incidents

// Factor 3: Technology overlap with recent victims
MATCH (o)-[:USES]->(tech:Technology)
MATCH (victim:Organization)-[:USES]->(tech)
MATCH (incident:Incident)-[:AFFECTED]->(victim)
WHERE incident.incident_date > datetime() - duration({days: 90})
WITH o, direct_threats, industry_incidents, 
     collect(DISTINCT incident) as tech_overlap_incidents

// Factor 4: Unpatched vulnerabilities being actively exploited
MATCH (o)-[:USES]->(tech:Technology)-[:HAS]->(vuln:Vulnerability)
WHERE vuln.exploitation_status.in_the_wild = true
  AND NOT EXISTS((o)-[:PATCHED]->(vuln))
WITH o, direct_threats, industry_incidents, tech_overlap_incidents,
     collect(vuln) as critical_vulns

// Calculate composite risk score
RETURN o.name as organization,
       size(direct_threats) * 0.4 +
       size(industry_incidents) * 0.2 +
       size(tech_overlap_incidents) * 0.2 +
       size(critical_vulns) * 0.2 as risk_score_30d,
       
       CASE 
         WHEN size(direct_threats) > 0 THEN 'Critical - Direct Targeting Observed'
         WHEN size(critical_vulns) > 5 THEN 'High - Multiple Critical Vulnerabilities'
         WHEN size(industry_incidents) > 10 THEN 'High - Industry Under Attack'
         ELSE 'Medium - Standard Risk Profile'
       END as risk_assessment,
       
       direct_threats[0].name as primary_threat,
       critical_vulns[0..3] as top_vulnerabilities,
       industry_incidents[0..3] as recent_peer_incidents
```

---

## 📊 Intelligence Correlation Patterns

### Pattern 1: Attack Precursor Detection
```cypher
// Identify attack precursors based on historical patterns
MATCH (future_victim:Organization {id: $org_id})
MATCH (past_incident:Incident)-[:AFFECTED]->(past_victim:Organization)
WHERE past_victim.industry = future_victim.industry

// Find what happened 30-90 days before past incidents
MATCH (precursor:Incident)-[:PRECEDED_BY]->(past_incident)
WHERE precursor.incident_date < past_incident.incident_date - duration({days: 30})
  AND precursor.incident_date > past_incident.incident_date - duration({days: 90})

// Check if similar precursors are happening now
MATCH (current_activity:Incident)
WHERE current_activity.type = precursor.type
  AND current_activity.incident_date > datetime() - duration({days: 30})
  AND (current_activity)-[:AFFECTED]->(:Organization {industry: future_victim.industry})

RETURN 
  future_victim.name as at_risk_organization,
  collect(DISTINCT precursor.type) as precursor_types,
  collect(DISTINCT current_activity.name) as current_precursor_activity,
  avg(duration.between(precursor.incident_date, past_incident.incident_date).days) as typical_days_to_attack,
  'HIGH RISK - Attack precursors detected' as alert
```

### Pattern 2: Supply Chain Attack Path Analysis
```cypher
// Trace all possible supply chain attack paths
MATCH path = (attacker:Organization {type: "Criminal"})
  -[:COMPROMISED|:TARGETS*1..6]->(supplier:Organization)
  -[:SUPPLIES_TO*1..4]->(target:Organization {id: $org_id})
  
WITH path, attacker, supplier, target,
     length(path) as path_length,
     [n in nodes(path) WHERE n:Organization AND n.company_profile.security_budget < 1000000] as weak_links

WHERE size(weak_links) > 0  // Path contains vulnerable organizations

RETURN 
  attacker.name as threat_actor,
  [n in weak_links | n.name] as vulnerable_suppliers,
  path_length as supply_chain_depth,
  
  CASE
    WHEN path_length <= 3 AND size(weak_links) > 0 THEN 'CRITICAL'
    WHEN path_length <= 5 AND size(weak_links) > 1 THEN 'HIGH'
    ELSE 'MEDIUM'
  END as risk_level,
  
  'Implement supplier security requirements for: ' + weak_links[0].name as immediate_action
ORDER BY path_length ASC, size(weak_links) DESC
LIMIT 10
```

---

This advanced schema enables true predictive intelligence by connecting:
- **Real incidents** to future risks
- **Actual exploits** to vulnerable systems  
- **Proven attack patterns** to current threats
- **Measured impacts** to business decisions

The "Now, Next, or Never" framework is built on empirical data, not theoretical risk scores, giving clients actionable intelligence for immediate decisions.