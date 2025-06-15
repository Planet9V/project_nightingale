# Project Seldon Knowledge Graph Schema Definitions
## Comprehensive Schema Architecture for Organizational Psychology

**Version**: 1.0  
**Date**: June 14, 2025  
**Status**: Implementation Ready  
**Dependencies**: ONTOLOGICAL_FRAMEWORK.md  

---

## 📋 Executive Summary

This document provides detailed schema definitions for Project Seldon's Knowledge Graph, implementing the enhanced ontological framework with concrete data structures, validation rules, and query patterns. These schemas enable the sophisticated modeling of organizational psychology, threat intelligence, and infrastructure relationships.

---

## 🎯 Core Entity Schemas

### Organization Entity Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://projectseldon.ai/schemas/organization/v1",
  "title": "Organization Entity",
  "type": "object",
  "required": ["id", "name", "type", "profile", "temporal"],
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^org:[a-z0-9-]+$",
      "description": "Unique organization identifier"
    },
    "name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255
    },
    "type": {
      "type": "string",
      "enum": ["energy", "water", "food", "transportation", "manufacturing", "financial", "government"]
    },
    "profile": {
      "$ref": "#/definitions/OrganizationalProfile"
    },
    "temporal": {
      "$ref": "#/definitions/TemporalMetadata"
    },
    "confidence": {
      "$ref": "#/definitions/ConfidenceScore"
    }
  },
  "definitions": {
    "OrganizationalProfile": {
      "type": "object",
      "properties": {
        "psychological": {
          "$ref": "#/definitions/PsychologicalDimension"
        },
        "structural": {
          "$ref": "#/definitions/StructuralDimension"
        },
        "behavioral": {
          "$ref": "#/definitions/BehavioralDimension"
        },
        "cultural": {
          "$ref": "#/definitions/CulturalDimension"
        }
      }
    }
  }
}
```

### Psychological Dimension Schema

```yaml
PsychologicalDimension:
  type: object
  required: [archetype, personality, dynamics]
  properties:
    archetype:
      type: object
      properties:
        primary:
          type: string
          enum: [Hero, Caregiver, Creator, Ruler, Sage, Explorer, 
                 Rebel, Magician, Innocent, Lover, Jester, Everyman]
        shadow:
          type: string
          enum: [Tyrant, Victim, Destroyer, Slave, Fool, Wanderer,
                 Conformist, Charlatan, Orphan, Addicted, Trickster, Nobody]
        strength:
          type: number
          minimum: 0
          maximum: 1
          
    personality:
      type: object
      properties:
        bigFive:
          type: object
          properties:
            openness: {type: number, minimum: 0, maximum: 100}
            conscientiousness: {type: number, minimum: 0, maximum: 100}
            extraversion: {type: number, minimum: 0, maximum: 100}
            agreeableness: {type: number, minimum: 0, maximum: 100}
            neuroticism: {type: number, minimum: 0, maximum: 100}
        
        mbti:
          type: string
          pattern: "^[EI][NS][TF][JP]$"
          
        enneagram:
          type: object
          properties:
            type: {type: integer, minimum: 1, maximum: 9}
            wing: {type: integer, minimum: 1, maximum: 9}
            instinct:
              type: string
              enum: [self-preservation, social, sexual]
              
    dynamics:
      type: object
      properties:
        defenses:
          type: array
          items:
            type: object
            properties:
              mechanism:
                type: string
                enum: [denial, projection, rationalization, repression,
                       displacement, sublimation, intellectualization]
              strength: {type: number, minimum: 0, maximum: 1}
              triggers:
                type: array
                items: {type: string}
                
        conflicts:
          type: array
          items:
            type: object
            properties:
              type:
                type: string
                enum: [approach-approach, avoidance-avoidance, 
                       approach-avoidance, double-approach-avoidance]
              parties:
                type: array
                items: {type: string}
              intensity: {type: number, minimum: 0, maximum: 1}
              
        motivations:
          type: array
          items:
            type: object
            properties:
              driver:
                type: string
                enum: [power, achievement, affiliation, security,
                       autonomy, purpose, mastery, growth]
              strength: {type: number, minimum: 0, maximum: 1}
              conscious: {type: boolean}
```

### Threat Actor Schema

```typescript
interface ThreatActorNode {
  // Identity
  id: string; // Format: "threat:group-name"
  aliases: string[];
  classification: ThreatClassification;
  
  // Capabilities
  capabilities: {
    technical: TechnicalCapability[];
    operational: OperationalCapability[];
    financial: FinancialCapability;
    human: HumanCapability;
  };
  
  // Psychology
  psychology: {
    motivation: Motivation[];
    riskTolerance: RiskProfile;
    decisionMaking: DecisionStyle;
    groupDynamics: GroupDynamic;
  };
  
  // Behavioral Patterns
  behavior: {
    ttpProfile: MitreAttackProfile;
    targetingPreferences: TargetingPattern[];
    operationalTempo: TempoPattern;
    evolutionTrajectory: EvolutionPath;
  };
  
  // Relationships
  relationships: {
    affiliations: Affiliation[];
    rivalries: Rivalry[];
    suppliers: SupplierRelation[];
    customers: CustomerRelation[];
  };
  
  // Temporal
  temporal: {
    firstSeen: Date;
    lastActive: Date;
    activityPeriods: ActivityPeriod[];
    lifecycle: ThreatLifecycle;
  };
}
```

### Infrastructure Node Schema

```graphql
type InfrastructureNode {
  # Identity
  id: ID! # Format: "infra:system-identifier"
  name: String!
  type: InfrastructureType!
  criticality: CriticalityLevel!
  
  # Technical Profile
  technical: TechnicalProfile!
  operational: OperationalProfile!
  
  # Dependencies
  dependencies: [Dependency!]!
  dependents: [Dependent!]!
  
  # Vulnerabilities
  vulnerabilities: [Vulnerability!]!
  exposures: [Exposure!]!
  
  # Protections
  protections: [Protection!]!
  resilience: ResilienceProfile!
  
  # Ownership
  owner: Organization!
  operators: [Operator!]!
  maintainers: [Maintainer!]!
}

type TechnicalProfile {
  architecture: Architecture!
  stack: TechnologyStack!
  interfaces: [Interface!]!
  dataFlows: [DataFlow!]!
  
  # Nested complexity
  components: [Component!]!
  configurations: [Configuration!]!
  integrations: [Integration!]!
}

enum InfrastructureType {
  SCADA
  DCS
  PLC
  HMI
  HISTORIAN
  OPC_SERVER
  NETWORK_DEVICE
  SECURITY_DEVICE
  COMPUTE_RESOURCE
  STORAGE_SYSTEM
}
```

---

## 🔗 Relationship Schemas

### Psychological Relationship Schema

```typescript
interface PsychologicalRelationship {
  // Identity
  id: string; // Format: "rel:psych:uuid"
  type: PsychRelationType;
  source: NodeReference;
  target: NodeReference;
  
  // Relationship Layers
  layers: {
    conscious: {
      stated: string;
      formalized: boolean;
      documented: Documentation[];
    };
    
    unconscious: {
      projection: ProjectionType;
      transference: TransferencePattern;
      countertransference: CountertransferencePattern;
      shadow: ShadowDynamic;
    };
    
    systemic: {
      role: SystemicRole;
      function: SystemicFunction;
      homeostasis: HomeostasisPattern;
    };
  };
  
  // Dynamics
  dynamics: {
    power: PowerDynamic;
    attachment: AttachmentStyle;
    communication: CommunicationPattern;
    conflict: ConflictPattern;
  };
  
  // Evolution
  evolution: {
    formation: Date;
    stages: RelationshipStage[];
    criticalEvents: CriticalEvent[];
    trajectory: TrajectoryPrediction;
  };
  
  // Influence
  influence: {
    direction: InfluenceDirection;
    strength: number; // 0.0 to 1.0
    mechanisms: InfluenceMechanism[];
    resistance: ResistancePattern[];
  };
}

enum PsychRelationType {
  DEPENDENCY = "dependency",
  CODEPENDENCY = "codependency",
  PROJECTION = "projection",
  IDENTIFICATION = "identification",
  RIVALRY = "rivalry",
  MENTORSHIP = "mentorship",
  ALLIANCE = "alliance",
  PARASITIC = "parasitic",
  SYMBIOTIC = "symbiotic"
}
```

### Threat Relationship Schema

```json
{
  "ThreatRelationship": {
    "type": "object",
    "properties": {
      "id": {"type": "string", "pattern": "^rel:threat:[a-z0-9-]+$"},
      "type": {
        "type": "string",
        "enum": ["targets", "collaborates", "competes", "supplies", "mimics", "evolves_from"]
      },
      "source": {"$ref": "#/definitions/ThreatActor"},
      "target": {"$ref": "#/definitions/Entity"},
      
      "operational": {
        "type": "object",
        "properties": {
          "frequency": {"type": "string", "enum": ["continuous", "periodic", "opportunistic", "rare"]},
          "intensity": {"type": "number", "minimum": 0, "maximum": 1},
          "sophistication": {"type": "number", "minimum": 0, "maximum": 10},
          "success_rate": {"type": "number", "minimum": 0, "maximum": 1}
        }
      },
      
      "temporal": {
        "type": "object",
        "properties": {
          "first_observed": {"type": "string", "format": "date-time"},
          "last_observed": {"type": "string", "format": "date-time"},
          "active_periods": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
                "intensity": {"type": "number"}
              }
            }
          }
        }
      }
    }
  }
}
```

---

## 📊 Temporal Schema Extensions

### Temporal State Tracking

```typescript
interface TemporalStateSchema {
  // State Identity
  nodeId: string;
  stateId: string;
  timestamp: Date;
  
  // State Snapshot
  snapshot: {
    attributes: Map<string, any>;
    relationships: RelationshipSnapshot[];
    metrics: MetricSnapshot[];
    confidence: ConfidenceSnapshot;
  };
  
  // Change Detection
  changes: {
    added: Change[];
    modified: Change[];
    removed: Change[];
    significance: number;
  };
  
  // Causality
  causality: {
    triggers: Trigger[];
    consequences: Consequence[];
    correlations: Correlation[];
  };
  
  // Predictions
  predictions: {
    nextState: StatePrediction;
    trajectory: TrajectoryPrediction;
    anomalies: AnomalyPrediction[];
  };
}

// Multi-resolution time series
interface TimeSeriesSchema {
  nodeId: string;
  metric: string;
  granularity: TemporalGranularity;
  
  dataPoints: {
    timestamp: Date;
    value: number;
    confidence: number;
    source: string;
  }[];
  
  aggregations: {
    min: number;
    max: number;
    mean: number;
    stdDev: number;
    trend: TrendDirection;
  };
  
  patterns: {
    seasonality: SeasonalPattern[];
    cycles: CyclicalPattern[];
    trends: TrendPattern[];
    anomalies: AnomalyPattern[];
  };
}
```

---

## 🎯 Confidence Scoring Schema

```yaml
ConfidenceScore:
  type: object
  required: [aggregate, factors, metadata]
  properties:
    aggregate:
      type: number
      minimum: 0
      maximum: 1
      description: Overall confidence score
      
    factors:
      type: object
      properties:
        source_reliability:
          type: object
          properties:
            score: {type: number, minimum: 0, maximum: 1}
            sources:
              type: array
              items:
                type: object
                properties:
                  id: {type: string}
                  type: {type: string}
                  reliability: {type: number}
                  weight: {type: number}
                  
        data_quality:
          type: object
          properties:
            completeness: {type: number, minimum: 0, maximum: 1}
            consistency: {type: number, minimum: 0, maximum: 1}
            accuracy: {type: number, minimum: 0, maximum: 1}
            timeliness: {type: number, minimum: 0, maximum: 1}
            
        corroboration:
          type: object
          properties:
            independent_sources: {type: integer, minimum: 0}
            agreement_level: {type: number, minimum: 0, maximum: 1}
            contradiction_count: {type: integer, minimum: 0}
            
    bayesian:
      type: object
      properties:
        prior: {type: number, minimum: 0, maximum: 1}
        likelihood: {type: number, minimum: 0, maximum: 1}
        posterior: {type: number, minimum: 0, maximum: 1}
        evidence:
          type: array
          items:
            type: object
            properties:
              id: {type: string}
              impact: {type: number}
              timestamp: {type: string, format: date-time}
              
    propagation:
      type: object
      properties:
        inherited_from:
          type: array
          items: {type: string}
        decay_factor: {type: number, minimum: 0, maximum: 1}
        reinforcement_count: {type: integer, minimum: 0}
        
    metadata:
      type: object
      properties:
        calculated_at: {type: string, format: date-time}
        algorithm_version: {type: string}
        calculation_time_ms: {type: integer}
        warnings:
          type: array
          items: {type: string}
```

---

## 🔍 Query Pattern Schemas

### Complex Query Schema

```graphql
type ComplexQuery {
  # Entity Filters
  entities: EntityFilter!
  
  # Relationship Filters
  relationships: RelationshipFilter!
  
  # Temporal Constraints
  temporal: TemporalFilter!
  
  # Confidence Thresholds
  confidence: ConfidenceFilter!
  
  # Aggregations
  aggregations: [AggregationType!]
  
  # Projections
  projections: ProjectionSpec!
}

input EntityFilter {
  types: [EntityType!]
  attributes: [AttributeFilter!]
  psychological: PsychologicalFilter
  behavioral: BehavioralFilter
}

input RelationshipFilter {
  types: [RelationshipType!]
  minStrength: Float
  maxHops: Int
  patterns: [PatternType!]
}

input TemporalFilter {
  timeRange: TimeRange
  granularity: TemporalGranularity
  includeHistory: Boolean
  includePredictions: Boolean
}
```

### Inference Query Schema

```typescript
interface InferenceQuery {
  // Query Type
  type: InferenceType;
  
  // Starting Points
  seeds: {
    entities: EntityReference[];
    patterns: PatternReference[];
    constraints: Constraint[];
  };
  
  // Reasoning Parameters
  reasoning: {
    depth: number;
    breadth: number;
    methods: ReasoningMethod[];
    confidence_threshold: number;
  };
  
  // Context
  context: {
    domain: DomainContext;
    temporal: TemporalContext;
    scenario: ScenarioContext;
  };
  
  // Output Specification
  output: {
    format: OutputFormat;
    detail_level: DetailLevel;
    include_provenance: boolean;
    include_alternatives: boolean;
  };
}

enum InferenceType {
  CAUSAL_CHAIN = "causal_chain",
  PATTERN_MATCH = "pattern_match",
  ANOMALY_DETECTION = "anomaly_detection",
  FUTURE_STATE = "future_state",
  MISSING_LINK = "missing_link",
  CONTRADICTION = "contradiction"
}
```

---

## 🛡️ Validation Rules

### Schema Validation Rules

```typescript
const ValidationRules = {
  // Entity Validation
  entity: {
    id: /^[a-z]+:[a-z0-9-]+$/,
    name: { minLength: 1, maxLength: 255 },
    requiredFields: ['id', 'type', 'profile', 'temporal'],
    customValidators: [
      validatePsychologicalCompleteness,
      validateTemporalConsistency,
      validateConfidenceFactors
    ]
  },
  
  // Relationship Validation
  relationship: {
    id: /^rel:[a-z]+:[a-z0-9-]+$/,
    requiredFields: ['id', 'type', 'source', 'target'],
    strengthRange: [0.0, 1.0],
    customValidators: [
      validateRelationshipSymmetry,
      validateTemporalOverlap,
      validateInfluenceDirectionality
    ]
  },
  
  // Temporal Validation
  temporal: {
    dateFormat: ISO8601,
    futureLimit: '10 years',
    pastLimit: '50 years',
    customValidators: [
      validateChronologicalOrder,
      validateStateTransitions,
      validatePredictionHorizon
    ]
  }
};
```

---

## 🚀 Implementation Guidelines

### Schema Evolution Strategy

1. **Version Management**
   - Semantic versioning for all schemas
   - Migration scripts for updates
   - Backward compatibility for 2 major versions

2. **Extension Points**
   - Custom attribute namespaces
   - Plugin-based validators
   - Dynamic schema loading

3. **Performance Optimization**
   - Indexed fields for common queries
   - Denormalized views for read performance
   - Lazy loading for nested structures

4. **Integration Points**
   - ETL pipeline mappings
   - Vector embedding generation
   - Graph database projections

---

*"The schema is not just structure, but the foundation for understanding."*

**Last Updated**: June 14, 2025  
**Next Review**: July 2025