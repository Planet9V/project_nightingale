# Project Seldon - API Documentation

## Overview

This document provides comprehensive API reference for all Project Seldon services. All APIs follow RESTful principles and return JSON responses.

## Base URLs

- **Development**: `http://localhost:{port}/api/v1`
- **Staging**: `https://staging.seldon.company.com/api/v1`
- **Production**: `https://api.seldon.company.com/v1`

## Authentication

All API endpoints require authentication using either JWT tokens or API keys.

### JWT Authentication
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key Authentication
```http
X-API-Key: sk_live_abcdef123456789
```

## Common Headers

```http
Content-Type: application/json
Accept: application/json
X-Request-ID: uuid-v4
X-Client-Version: 1.0.0
```

## Response Format

### Success Response
```json
{
  "success": true,
  "data": {
    // Response data
  },
  "metadata": {
    "timestamp": "2025-06-13T20:30:00Z",
    "version": "1.0.0",
    "requestId": "uuid-v4"
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found",
    "details": {
      // Additional error details
    }
  },
  "metadata": {
    "timestamp": "2025-06-13T20:30:00Z",
    "requestId": "uuid-v4"
  }
}
```

---

# Intelligence Engine API (Port 8000)

## Endpoints

### Analyze Prospect
Performs comprehensive threat analysis for a specific prospect.

**POST** `/api/v1/intelligence/analyze`

#### Request Body
```json
{
  "prospect": "Consumers Energy",
  "analysisType": "comprehensive",
  "options": {
    "includeMitreMapping": true,
    "includeVulnerabilities": true,
    "includeThreatActors": true,
    "timeframe": "last_90_days"
  }
}
```

#### Response
```json
{
  "success": true,
  "data": {
    "analysisId": "ana_2K3nX9mP",
    "prospect": {
      "name": "Consumers Energy",
      "sector": "energy",
      "subsector": "electric_utility"
    },
    "threatAssessment": {
      "overallRisk": "HIGH",
      "riskScore": 8.5,
      "criticalFindings": 3
    },
    "threats": [
      {
        "actorName": "Volt Typhoon",
        "sophistication": "HIGH",
        "likelihood": 0.75,
        "impact": "CRITICAL",
        "ttps": ["T1190", "T1133", "T1078"]
      }
    ],
    "vulnerabilities": [
      {
        "cve": "CVE-2024-12345",
        "cvssScore": 9.8,
        "exploitAvailable": true,
        "affectedSystems": ["SCADA", "HMI"]
      }
    ],
    "mitreMapping": {
      "tactics": ["Initial Access", "Persistence"],
      "techniques": ["T1190", "T1133"],
      "mitigations": ["M1036", "M1037"]
    }
  }
}
```

### Get Threat Actors
Retrieves threat actors based on filters.

**GET** `/api/v1/intelligence/threat-actors`

#### Query Parameters
- `sector` (string): Filter by target sector
- `sophistication` (string): LOW, MEDIUM, HIGH
- `active` (boolean): Currently active actors
- `limit` (integer): Max results (default: 20)
- `offset` (integer): Pagination offset

#### Response
```json
{
  "success": true,
  "data": {
    "threatActors": [
      {
        "id": "ta_V0ltTyph00n",
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda"],
        "origin": "China",
        "sophistication": "HIGH",
        "targetSectors": ["energy", "water", "transportation"],
        "objectives": ["espionage", "pre-positioning"],
        "knownTTPs": ["T1190", "T1133", "T1078"],
        "lastActivity": "2025-06-10T00:00:00Z"
      }
    ],
    "pagination": {
      "total": 42,
      "limit": 20,
      "offset": 0,
      "hasMore": true
    }
  }
}
```

### Search Vulnerabilities
Search for vulnerabilities by CVE or criteria.

**POST** `/api/v1/intelligence/vulnerabilities/search`

#### Request Body
```json
{
  "query": "SCADA",
  "filters": {
    "cvssMin": 7.0,
    "exploitAvailable": true,
    "publishedAfter": "2024-01-01",
    "vendors": ["schneider", "siemens"]
  }
}
```

#### Response
```json
{
  "success": true,
  "data": {
    "vulnerabilities": [
      {
        "cve": "CVE-2024-12345",
        "description": "Remote code execution in SCADA HMI",
        "cvssScore": 9.8,
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploitAvailable": true,
        "cisaKev": true,
        "affectedProducts": [
          {
            "vendor": "Schneider Electric",
            "product": "EcoStruxure",
            "versions": ["2021.1", "2021.2"]
          }
        ],
        "mitigations": [
          "Apply vendor patch",
          "Network segmentation"
        ]
      }
    ]
  }
}
```

### Predict Threats (Psychohistory)
Uses psychohistory algorithms to predict future threats.

**POST** `/api/v1/intelligence/predict`

#### Request Body
```json
{
  "target": {
    "type": "sector",
    "value": "energy"
  },
  "timeframe": {
    "start": "2025-07-01",
    "end": "2025-12-31"
  },
  "factors": {
    "includeGeopolitical": true,
    "includeEconomic": true,
    "includeTechnological": true
  }
}
```

#### Response
```json
{
  "success": true,
  "data": {
    "predictions": [
      {
        "event": "Major ransomware campaign targeting utilities",
        "probability": 0.73,
        "timeframe": "Q3 2025",
        "confidence": 0.85,
        "indicators": [
          "Increased reconnaissance activity",
          "New ransomware variants in development",
          "Threat actor collaboration patterns"
        ],
        "recommendations": [
          "Enhance backup strategies",
          "Implement zero-trust architecture",
          "Conduct tabletop exercises"
        ]
      }
    ],
    "methodology": "psychohistory_v2",
    "dataPoints": 1847293
  }
}
```

---

# EAB Generator API (Port 8001)

## Endpoints

### Generate Express Attack Brief
Creates a comprehensive Express Attack Brief.

**POST** `/api/v1/eab/generate`

#### Request Body
```json
{
  "sector": "energy",
  "threatActor": "Volt Typhoon",
  "prospect": "Consumers Energy",
  "options": {
    "includeTimeline": true,
    "includeVisuals": true,
    "executiveLength": "concise"
  }
}
```

#### Response
```json
{
  "success": true,
  "data": {
    "eabId": "eab_7K9mN3xP",
    "title": "Volt Typhoon Threatens Energy Infrastructure",
    "executiveSummary": "Chinese state-sponsored threat actor...",
    "threatProfile": {
      "actor": "Volt Typhoon",
      "motivation": "Espionage and pre-positioning",
      "capabilities": "HIGH",
      "historicalActivity": [...]
    },
    "attackTimeline": {
      "phases": [
        {
          "phase": "Initial Access",
          "duration": "2-4 weeks",
          "techniques": ["T1190", "T1133"],
          "description": "Exploitation of public-facing applications"
        }
      ]
    },
    "mitreMapping": {
      "primary": ["T1190", "T1078", "T1053"],
      "secondary": ["T1055", "T1003"]
    },
    "recommendations": [
      {
        "priority": "CRITICAL",
        "action": "Patch vulnerable systems",
        "timeline": "Immediate"
      }
    ],
    "artifacts": {
      "pdf": "https://api.seldon.com/artifacts/eab_7K9mN3xP.pdf",
      "markdown": "https://api.seldon.com/artifacts/eab_7K9mN3xP.md"
    }
  }
}
```

### Get EAB Templates
Retrieves available EAB templates.

**GET** `/api/v1/eab/templates`

#### Response
```json
{
  "success": true,
  "data": {
    "templates": [
      {
        "id": "tpl_energy_sector",
        "name": "Energy Sector Template",
        "description": "Optimized for energy and utility companies",
        "sections": ["executive_summary", "threat_profile", "timeline", "mitigations"]
      },
      {
        "id": "tpl_manufacturing",
        "name": "Manufacturing Template",
        "description": "Focused on OT/ICS environments",
        "sections": ["executive_summary", "ot_risks", "supply_chain", "recommendations"]
      }
    ]
  }
}
```

### Validate EAB
Validates an EAB against quality standards.

**POST** `/api/v1/eab/validate`

#### Request Body
```json
{
  "eabId": "eab_7K9mN3xP",
  "validationLevel": "comprehensive"
}
```

#### Response
```json
{
  "success": true,
  "data": {
    "valid": true,
    "score": 92,
    "checks": {
      "completeness": {
        "passed": true,
        "score": 95,
        "details": "All required sections present"
      },
      "accuracy": {
        "passed": true,
        "score": 90,
        "details": "MITRE mappings verified"
      },
      "readability": {
        "passed": true,
        "score": 88,
        "details": "Executive-friendly language"
      }
    },
    "improvements": [
      "Consider adding more specific timeline details",
      "Include budget impact estimates"
    ]
  }
}
```

---

# Report Generator API (Port 8002)

## Endpoints

### Generate Executive Concierge Report
Creates a personalized executive intelligence report.

**POST** `/api/v1/reports/executive-concierge`

#### Request Body
```json
{
  "prospect": "American Water Works",
  "theme": "ITC",
  "personalization": {
    "executiveName": "Sarah Johnson",
    "executiveRole": "CISO",
    "companyContext": {
      "recentIncidents": true,
      "regulatoryPressure": "high",
      "digitalTransformation": "active"
    }
  },
  "sections": {
    "executiveSummary": true,
    "threatLandscape": true,
    "peerAnalysis": true,
    "recommendations": true,
    "nextSteps": true
  }
}
```

#### Response
```json
{
  "success": true,
  "data": {
    "reportId": "rpt_9M3nK7xL",
    "title": "Critical Infrastructure Protection: ITC Convergence",
    "prospect": "American Water Works",
    "theme": "ITC",
    "sections": {
      "executiveSummary": "As the largest water utility in the US...",
      "threatLandscape": {
        "currentThreats": [...],
        "emergingRisks": [...],
        "sectorTrends": [...]
      },
      "peerAnalysis": {
        "incidents": [...],
        "investments": [...],
        "maturityComparison": {...}
      }
    },
    "artifacts": {
      "pdf": "https://api.seldon.com/artifacts/rpt_9M3nK7xL.pdf",
      "docx": "https://api.seldon.com/artifacts/rpt_9M3nK7xL.docx"
    }
  }
}
```

### Generate Landing Page
Creates a themed landing page for campaigns.

**POST** `/api/v1/reports/landing-page`

#### Request Body
```json
{
  "theme": "ransomware",
  "sector": "manufacturing",
  "campaign": "Q3_2025_Manufacturing_Ransomware",
  "content": {
    "headline": "Stop Ransomware Before It Stops Your Production",
    "statistics": [
      {
        "value": "73%",
        "description": "of manufacturers hit by ransomware in 2024"
      }
    ],
    "caseStudies": ["colonial_pipeline", "jbs_foods"],
    "callToAction": {
      "primary": "Get Your Free Assessment",
      "secondary": "Download Industry Report"
    }
  }
}
```

### Generate Nurture Sequence
Creates a three-part email nurture sequence.

**POST** `/api/v1/reports/nurture-sequence`

#### Request Body
```json
{
  "prospect": "Consumers Energy",
  "theme": "SCA",
  "sequence": {
    "email1": {
      "timing": "immediate",
      "focus": "awareness"
    },
    "email2": {
      "timing": "day_3",
      "focus": "education"
    },
    "email3": {
      "timing": "day_7",
      "focus": "action"
    }
  },
  "personalization": {
    "recipientName": "John Smith",
    "recipientTitle": "VP of Operations",
    "painPoints": ["supply chain visibility", "third-party risk"]
  }
}
```

### Generate AM Playbook
Creates an Account Manager playbook for a prospect.

**POST** `/api/v1/reports/am-playbook`

#### Request Body
```json
{
  "accountManager": "Jim Vranicar",
  "prospect": "PG&E",
  "includeAppendix": true,
  "sections": {
    "executiveContacts": true,
    "engagementStrategy": true,
    "competitiveAnalysis": true,
    "talkingPoints": true,
    "objectionHandling": true
  }
}
```

---

# WebSocket Events

## Real-time Intelligence Updates

### Connection
```javascript
const ws = new WebSocket('wss://api.seldon.com/v1/intelligence/stream');

ws.on('open', () => {
  ws.send(JSON.stringify({
    type: 'subscribe',
    channels: ['threats', 'vulnerabilities'],
    filters: {
      sectors: ['energy', 'water'],
      severity: ['critical', 'high']
    }
  }));
});
```

### Event Types

#### Threat Alert
```json
{
  "type": "threat_alert",
  "timestamp": "2025-06-13T20:30:00Z",
  "data": {
    "threatActor": "Volt Typhoon",
    "activity": "New campaign detected",
    "targets": ["energy_sector"],
    "confidence": 0.85
  }
}
```

#### Vulnerability Alert
```json
{
  "type": "vulnerability_alert",
  "timestamp": "2025-06-13T20:30:00Z",
  "data": {
    "cve": "CVE-2025-12345",
    "severity": "CRITICAL",
    "affectedSectors": ["manufacturing"],
    "exploitDetected": true
  }
}
```

---

# Rate Limiting

All APIs implement rate limiting:

| Tier | Requests/Hour | Burst |
|------|--------------|-------|
| Free | 100 | 10 |
| Basic | 1,000 | 50 |
| Pro | 10,000 | 200 |
| Enterprise | Unlimited | Custom |

Rate limit headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1623456789
```

---

# Error Codes

| Code | Description |
|------|-------------|
| `AUTH_REQUIRED` | Authentication required |
| `AUTH_INVALID` | Invalid credentials |
| `RATE_LIMITED` | Rate limit exceeded |
| `RESOURCE_NOT_FOUND` | Resource not found |
| `VALIDATION_ERROR` | Invalid request data |
| `INTERNAL_ERROR` | Server error |
| `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

---

# SDK Examples

## JavaScript/TypeScript
```typescript
import { SeldonClient } from '@project-seldon/sdk';

const client = new SeldonClient({
  apiKey: process.env.SELDON_API_KEY,
  environment: 'production'
});

// Analyze prospect
const analysis = await client.intelligence.analyze({
  prospect: 'Consumers Energy',
  analysisType: 'comprehensive'
});

// Generate EAB
const eab = await client.eab.generate({
  sector: 'energy',
  threatActor: 'Volt Typhoon'
});
```

## Python
```python
from seldon import SeldonClient

client = SeldonClient(
    api_key=os.environ['SELDON_API_KEY'],
    environment='production'
)

# Analyze prospect
analysis = client.intelligence.analyze(
    prospect='Consumers Energy',
    analysis_type='comprehensive'
)

# Generate report
report = client.reports.executive_concierge(
    prospect='American Water Works',
    theme='ITC'
)
```

---

# Webhooks

Configure webhooks to receive real-time notifications:

## Webhook Configuration
```json
{
  "url": "https://your-app.com/webhooks/seldon",
  "events": ["analysis.complete", "eab.generated", "threat.detected"],
  "secret": "whsec_abcdef123456",
  "active": true
}
```

## Webhook Payload
```json
{
  "id": "evt_123456",
  "type": "analysis.complete",
  "timestamp": "2025-06-13T20:30:00Z",
  "data": {
    "analysisId": "ana_2K3nX9mP",
    "prospect": "Consumers Energy",
    "status": "complete"
  }
}
```

---

# API Versioning

- Current version: `v1`
- Version in URL: `/api/v1/`
- Deprecation notice: 6 months
- Sunset period: 12 months

---

# Support

- **Documentation**: https://docs.seldon.company.com
- **Status Page**: https://status.seldon.company.com
- **Support Email**: api-support@seldon.company.com
- **Developer Forum**: https://forum.seldon.company.com