# MCP Failover System Dashboard Configuration

## Real-time Monitoring Dashboard

### 1. Service Health Matrix

```yaml
dashboard:
  name: "MCP Service Health Overview"
  refresh: "5s"
  
  panels:
    - title: "Service Status Grid"
      type: "status-grid"
      position: { x: 0, y: 0, w: 12, h: 4 }
      data:
        services:
          - name: "Pinecone"
            metrics:
              - health_score
              - response_time
              - error_rate
            thresholds:
              healthy: "> 0.9"
              warning: "> 0.7"
              critical: "<= 0.7"
          
          - name: "Neo4j"
            metrics:
              - health_score
              - query_latency
              - connection_pool_usage
            thresholds:
              healthy: "> 0.9"
              warning: "> 0.7"
              critical: "<= 0.7"
          
          - name: "Graphlit"
            metrics:
              - health_score
              - api_availability
              - content_sync_lag
            thresholds:
              healthy: "> 0.95"
              warning: "> 0.8"
              critical: "<= 0.8"
```

### 2. Failover Status Panel

```json
{
  "panel": {
    "title": "Failover Status & History",
    "type": "table",
    "position": { "x": 0, "y": 4, "w": 8, "h": 6 },
    "columns": [
      { "field": "service", "header": "Service" },
      { "field": "current_endpoint", "header": "Active Endpoint" },
      { "field": "last_failover", "header": "Last Failover" },
      { "field": "failover_count", "header": "24h Failovers" },
      { "field": "uptime", "header": "Uptime %" }
    ],
    "data_source": "mcp_failover_metrics"
  }
}
```

### 3. Circuit Breaker Status

```javascript
// Circuit Breaker Visualization Config
const circuitBreakerConfig = {
  title: "Circuit Breaker Status",
  type: "circuit-diagram",
  position: { x: 8, y: 4, w: 4, h: 6 },
  services: [
    {
      name: "Pinecone",
      states: ["CLOSED", "OPEN", "HALF_OPEN"],
      colors: {
        CLOSED: "#28a745",
        OPEN: "#dc3545",
        HALF_OPEN: "#ffc107"
      }
    },
    {
      name: "Neo4j",
      states: ["CLOSED", "OPEN", "HALF_OPEN"]
    },
    {
      name: "Tavily",
      states: ["CLOSED", "OPEN", "HALF_OPEN"]
    }
  ]
};
```

### 4. Performance Metrics

```yaml
performance_panel:
  title: "Service Performance Metrics"
  type: "multi-line-chart"
  position: { x: 0, y: 10, w: 12, h: 6 }
  
  series:
    - name: "Pinecone Query Latency"
      metric: "pinecone_query_latency_ms"
      color: "#007bff"
      
    - name: "Neo4j Transaction Time"
      metric: "neo4j_transaction_time_ms"
      color: "#28a745"
      
    - name: "Graphlit API Response"
      metric: "graphlit_api_response_ms"
      color: "#ffc107"
      
  time_range: "1h"
  aggregation: "avg"
  interval: "1m"
```

### 5. Alert Configuration

```json
{
  "alerts": [
    {
      "name": "Critical Service Down",
      "condition": "health_score < 0.3 for 30s",
      "services": ["pinecone", "neo4j", "graphlit"],
      "severity": "critical",
      "actions": [
        "trigger_failover",
        "notify_oncall",
        "create_incident"
      ]
    },
    {
      "name": "Degraded Performance",
      "condition": "response_time > 5000ms for 2m",
      "severity": "warning",
      "actions": [
        "notify_team",
        "log_event"
      ]
    },
    {
      "name": "Failover Completed",
      "condition": "failover_event",
      "severity": "info",
      "actions": [
        "update_dashboard",
        "log_event",
        "notify_stakeholders"
      ]
    }
  ]
}
```

### 6. Grafana Dashboard JSON

```json
{
  "dashboard": {
    "title": "MCP Failover System",
    "uid": "mcp-failover-001",
    "tags": ["mcp", "failover", "monitoring"],
    "timezone": "browser",
    "refresh": "5s",
    
    "panels": [
      {
        "id": 1,
        "title": "Service Health Heatmap",
        "type": "heatmap",
        "gridPos": { "x": 0, "y": 0, "w": 12, "h": 8 },
        "targets": [
          {
            "expr": "mcp_service_health_score",
            "legendFormat": "{{service}}"
          }
        ],
        "options": {
          "colorScheme": "RdYlGn",
          "reverseColors": false
        }
      },
      {
        "id": 2,
        "title": "Failover Events Timeline",
        "type": "timeline",
        "gridPos": { "x": 0, "y": 8, "w": 12, "h": 6 },
        "targets": [
          {
            "expr": "mcp_failover_events",
            "format": "table"
          }
        ]
      },
      {
        "id": 3,
        "title": "RTO/RPO Compliance",
        "type": "gauge",
        "gridPos": { "x": 0, "y": 14, "w": 6, "h": 6 },
        "targets": [
          {
            "expr": "mcp_rto_compliance_percentage"
          }
        ],
        "thresholds": {
          "steps": [
            { "value": 0, "color": "red" },
            { "value": 80, "color": "yellow" },
            { "value": 95, "color": "green" }
          ]
        }
      },
      {
        "id": 4,
        "title": "Circuit Breaker States",
        "type": "stat",
        "gridPos": { "x": 6, "y": 14, "w": 6, "h": 6 },
        "targets": [
          {
            "expr": "mcp_circuit_breaker_state",
            "legendFormat": "{{service}}"
          }
        ],
        "options": {
          "colorMode": "background",
          "graphMode": "none"
        }
      }
    ]
  }
}
```

### 7. Prometheus Metrics

```yaml
# prometheus-mcp-metrics.yml
groups:
  - name: mcp_failover
    interval: 5s
    rules:
      - record: mcp_service_health_score
        expr: |
          (
            mcp_health_check_success_total /
            mcp_health_check_total
          ) * 100
          
      - record: mcp_failover_rate
        expr: |
          rate(mcp_failover_events_total[5m])
          
      - record: mcp_circuit_breaker_open_ratio
        expr: |
          sum(mcp_circuit_breaker_state == 2) by (service) /
          count(mcp_circuit_breaker_state) by (service)
          
      - record: mcp_recovery_time_seconds
        expr: |
          histogram_quantile(0.95,
            rate(mcp_recovery_duration_seconds_bucket[5m])
          )
```

### 8. Datadog Monitor Configuration

```json
{
  "monitors": [
    {
      "name": "MCP Service Health Check",
      "type": "service check",
      "query": "\"mcp.health_check\".over(\"service:pinecone\").last(2).count_by_status()",
      "message": "Service {{service.name}} is experiencing issues @oncall-team",
      "thresholds": {
        "critical": 2,
        "warning": 1
      },
      "notify_no_data": true,
      "no_data_timeframe": 5
    },
    {
      "name": "MCP Failover Rate",
      "type": "metric alert",
      "query": "sum(last_5m):sum:mcp.failover.count{*} by {service} > 3",
      "message": "High failover rate detected for {{service.name}}",
      "thresholds": {
        "critical": 3,
        "warning": 2
      }
    }
  ]
}
```

### 9. Custom Dashboard HTML

```html
<!DOCTYPE html>
<html>
<head>
    <title>MCP Failover Dashboard</title>
    <style>
        .service-card {
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 10px;
            display: inline-block;
            width: 300px;
        }
        .healthy { border-color: #28a745; background: #d4edda; }
        .warning { border-color: #ffc107; background: #fff3cd; }
        .critical { border-color: #dc3545; background: #f8d7da; }
        .metric { margin: 5px 0; }
        .metric-label { font-weight: bold; }
        .metric-value { float: right; }
    </style>
</head>
<body>
    <h1>MCP Service Failover Status</h1>
    
    <div id="services-container">
        <!-- Service cards will be dynamically inserted here -->
    </div>
    
    <div id="failover-history">
        <h2>Recent Failover Events</h2>
        <table id="failover-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Service</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Duration</th>
                </tr>
            </thead>
            <tbody>
                <!-- Failover events will be inserted here -->
            </tbody>
        </table>
    </div>
    
    <script>
        // WebSocket connection for real-time updates
        const ws = new WebSocket('ws://localhost:8080/mcp-metrics');
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };
        
        function updateDashboard(data) {
            // Update service cards
            const container = document.getElementById('services-container');
            container.innerHTML = '';
            
            data.services.forEach(service => {
                const card = createServiceCard(service);
                container.appendChild(card);
            });
            
            // Update failover history
            updateFailoverHistory(data.failoverEvents);
        }
        
        function createServiceCard(service) {
            const card = document.createElement('div');
            card.className = `service-card ${service.status}`;
            
            card.innerHTML = `
                <h3>${service.name}</h3>
                <div class="metric">
                    <span class="metric-label">Health Score:</span>
                    <span class="metric-value">${(service.healthScore * 100).toFixed(1)}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Response Time:</span>
                    <span class="metric-value">${service.responseTime}ms</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Active Endpoint:</span>
                    <span class="metric-value">${service.activeEndpoint}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Circuit Breaker:</span>
                    <span class="metric-value">${service.circuitBreakerState}</span>
                </div>
            `;
            
            return card;
        }
        
        function updateFailoverHistory(events) {
            const tbody = document.querySelector('#failover-table tbody');
            tbody.innerHTML = '';
            
            events.slice(0, 10).forEach(event => {
                const row = tbody.insertRow();
                row.insertCell(0).textContent = new Date(event.timestamp).toLocaleString();
                row.insertCell(1).textContent = event.service;
                row.insertCell(2).textContent = event.from;
                row.insertCell(3).textContent = event.to;
                row.insertCell(4).textContent = `${event.duration}ms`;
            });
        }
        
        // Initial load
        fetch('/api/mcp-status')
            .then(response => response.json())
            .then(data => updateDashboard(data));
    </script>
</body>
</html>
```

### 10. Mobile Alert Configuration

```yaml
# PagerDuty Integration
pagerduty:
  services:
    - name: "MCP Critical Services"
      integration_key: "${PAGERDUTY_KEY}"
      escalation_policy: "infrastructure-oncall"
      
  alerts:
    - trigger: "service_down"
      severity: "critical"
      dedupe_key: "mcp-{{service}}-down"
      
    - trigger: "multiple_failovers"
      severity: "high"
      dedupe_key: "mcp-failover-storm"

# Slack Notifications
slack:
  webhook_url: "${SLACK_WEBHOOK}"
  channels:
    - name: "#mcp-alerts"
      events: ["failover", "recovery", "circuit_breaker_open"]
      
    - name: "#infrastructure"
      events: ["critical_failure", "rto_breach"]

# SMS Alerts (Twilio)
sms:
  enabled: true
  recipients:
    - "+1234567890" # On-call engineer
    - "+0987654321" # Backup engineer
  triggers:
    - "tier1_service_down"
    - "cascade_failure_detected"
```

## Usage Instructions

1. **Deploy Dashboards**: Import JSON configurations into Grafana
2. **Configure Alerts**: Set up PagerDuty and Slack webhooks
3. **Test Visualizations**: Run sample data through the system
4. **Mobile Access**: Ensure dashboards are mobile-responsive
5. **Documentation**: Update runbooks with dashboard URLs

## Dashboard Access

- **Grafana**: https://monitoring.company.com/d/mcp-failover
- **Custom Dashboard**: https://mcp-dashboard.company.com
- **Mobile App**: Download "MCP Monitor" from app store
- **API Endpoint**: https://api.company.com/mcp/status