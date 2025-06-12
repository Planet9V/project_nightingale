# Project Seldon Administrative Guide
**Version**: 1.0  
**Last Updated**: December 6, 2025  
**Classification**: Internal Use Only

## Table of Contents
1. [System Overview](#system-overview)
2. [System Administration Procedures](#system-administration-procedures)
3. [Maintenance Schedules](#maintenance-schedules)
4. [User Management](#user-management)
5. [Backup and Recovery](#backup-and-recovery)
6. [Performance Monitoring](#performance-monitoring)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Security Best Practices](#security-best-practices)
9. [Integration Management](#integration-management)
10. [Data Quality Assurance](#data-quality-assurance)
11. [Emergency Response](#emergency-response)

## 1. System Overview

### Core Components
- **Neo4j Database**: Graph database for relationship mapping
- **Pinecone Vector Database**: Similarity search and embeddings
- **MCP Servers**: Integration layer for external services
- **API Gateway**: Unified access point for all services

### Architecture
```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   MCP Servers   │────▶│  API Gateway │◀────│  Client Apps    │
└─────────────────┘     └──────────────┘     └─────────────────┘
         │                      │                      │
         ▼                      ▼                      ▼
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│     Neo4j       │     │   Pinecone   │     │   Monitoring    │
└─────────────────┘     └──────────────┘     └─────────────────┘
```

## 2. System Administration Procedures

### 2.1 Neo4j Administration

#### Start/Stop Neo4j
```bash
# Start Neo4j
sudo systemctl start neo4j

# Stop Neo4j
sudo systemctl stop neo4j

# Restart Neo4j
sudo systemctl restart neo4j

# Check status
sudo systemctl status neo4j
```

#### Neo4j Configuration
```bash
# Edit configuration
sudo nano /etc/neo4j/neo4j.conf

# Key settings to monitor:
# dbms.memory.heap.initial_size=2g
# dbms.memory.heap.max_size=4g
# dbms.memory.pagecache.size=2g
# dbms.connector.bolt.listen_address=:7687
# dbms.connector.http.listen_address=:7474
```

#### Database Health Check
```cypher
// Check database status
CALL dbms.components() YIELD name, versions, edition
RETURN name, versions, edition;

// Check node counts
MATCH (n) RETURN labels(n) AS label, count(n) AS count
ORDER BY count DESC;

// Check relationship counts
MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count
ORDER BY count DESC;

// Check constraints and indexes
SHOW CONSTRAINTS;
SHOW INDEXES;
```

### 2.2 Pinecone Administration

#### Initialize Pinecone Client
```python
import pinecone
import os

# Initialize
pinecone.init(
    api_key=os.environ.get('PINECONE_API_KEY'),
    environment=os.environ.get('PINECONE_ENV')
)

# List indexes
index_list = pinecone.list_indexes()
print(f"Available indexes: {index_list}")
```

#### Index Management
```python
# Create index
def create_index(index_name, dimension=1536, metric='cosine'):
    if index_name not in pinecone.list_indexes():
        pinecone.create_index(
            name=index_name,
            dimension=dimension,
            metric=metric,
            metadata_config={
                'indexed': ['prospect_id', 'theme', 'sector']
            }
        )
    
# Delete index (CAUTION)
def delete_index(index_name):
    if index_name in pinecone.list_indexes():
        pinecone.delete_index(index_name)

# Get index stats
def get_index_stats(index_name):
    index = pinecone.Index(index_name)
    return index.describe_index_stats()
```

## 3. Maintenance Schedules

### 3.1 Daily Tasks
```bash
#!/bin/bash
# daily_maintenance.sh

echo "=== Daily Maintenance Started: $(date) ==="

# 1. Check system health
echo "Checking Neo4j health..."
cypher-shell -u neo4j -p $NEO4J_PASSWORD \
    "CALL dbms.components() YIELD name, versions RETURN name, versions;"

# 2. Check disk space
echo "Checking disk space..."
df -h | grep -E "(neo4j|pinecone|seldon)"

# 3. Verify API endpoints
echo "Testing API endpoints..."
curl -s http://localhost:8080/health | jq .

# 4. Check error logs
echo "Recent errors (last 24h)..."
journalctl -u neo4j --since "24 hours ago" | grep ERROR | tail -20

echo "=== Daily Maintenance Completed: $(date) ==="
```

### 3.2 Weekly Tasks
```bash
#!/bin/bash
# weekly_maintenance.sh

echo "=== Weekly Maintenance Started: $(date) ==="

# 1. Optimize Neo4j
echo "Optimizing Neo4j database..."
cypher-shell -u neo4j -p $NEO4J_PASSWORD \
    "CALL db.checkpoint();"

# 2. Update statistics
echo "Updating database statistics..."
cypher-shell -u neo4j -p $NEO4J_PASSWORD \
    "CALL db.stats.clear(); CALL db.stats.collect();"

# 3. Clean old logs
echo "Cleaning logs older than 30 days..."
find /var/log/neo4j -name "*.log" -mtime +30 -delete
find /var/log/seldon -name "*.log" -mtime +30 -delete

# 4. Generate performance report
python3 /opt/seldon/scripts/generate_weekly_report.py

echo "=== Weekly Maintenance Completed: $(date) ==="
```

### 3.3 Monthly Tasks
```bash
#!/bin/bash
# monthly_maintenance.sh

echo "=== Monthly Maintenance Started: $(date) ==="

# 1. Full backup
echo "Performing full backup..."
/opt/seldon/scripts/full_backup.sh

# 2. Security audit
echo "Running security audit..."
/opt/seldon/scripts/security_audit.sh

# 3. Update dependencies
echo "Checking for updates..."
apt update && apt list --upgradable | grep -E "(neo4j|python|node)"

# 4. Performance baseline
echo "Capturing performance baseline..."
/opt/seldon/scripts/performance_baseline.sh

echo "=== Monthly Maintenance Completed: $(date) ==="
```

## 4. User Management

### 4.1 Neo4j User Management
```cypher
// Create user
CREATE USER seldon_admin SET PASSWORD 'SecurePass123!' CHANGE REQUIRED;

// Grant roles
GRANT ROLE admin TO seldon_admin;

// Create read-only user
CREATE USER seldon_reader SET PASSWORD 'ReadOnly123!' CHANGE NOT REQUIRED;
GRANT ROLE reader TO seldon_reader;

// List users
SHOW USERS;

// Revoke access
REVOKE ROLE admin FROM seldon_admin;

// Delete user
DROP USER seldon_reader;
```

### 4.2 API Access Control
```python
# user_management.py
import hashlib
import secrets
from datetime import datetime, timedelta

class UserManager:
    def create_api_key(self, user_id, permissions):
        """Generate API key for user"""
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store in database
        query = """
        CREATE (k:APIKey {
            id: $key_hash,
            user_id: $user_id,
            permissions: $permissions,
            created: datetime(),
            expires: datetime() + duration({days: 90})
        })
        """
        # Execute query...
        
        return api_key
    
    def validate_api_key(self, api_key):
        """Validate API key and check permissions"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        query = """
        MATCH (k:APIKey {id: $key_hash})
        WHERE k.expires > datetime()
        RETURN k.user_id AS user_id, k.permissions AS permissions
        """
        # Execute and return result...
```

## 5. Backup and Recovery

### 5.1 Neo4j Backup
```bash
#!/bin/bash
# neo4j_backup.sh

BACKUP_DIR="/backup/neo4j/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# Stop database for consistency
echo "Stopping Neo4j for backup..."
sudo systemctl stop neo4j

# Backup data
echo "Backing up Neo4j data..."
tar -czf $BACKUP_DIR/neo4j_data.tar.gz /var/lib/neo4j/data/

# Backup configuration
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/neo4j_config.tar.gz /etc/neo4j/

# Start database
echo "Starting Neo4j..."
sudo systemctl start neo4j

# Verify backup
echo "Backup completed. Size: $(du -sh $BACKUP_DIR)"
```

### 5.2 Pinecone Backup
```python
# pinecone_backup.py
import pinecone
import json
from datetime import datetime

def backup_pinecone_index(index_name, backup_path):
    """Backup Pinecone index data"""
    index = pinecone.Index(index_name)
    
    # Get all vectors
    stats = index.describe_index_stats()
    total_vectors = stats['total_vector_count']
    
    backup_data = {
        'index_name': index_name,
        'timestamp': datetime.now().isoformat(),
        'total_vectors': total_vectors,
        'vectors': []
    }
    
    # Fetch vectors in batches
    batch_size = 100
    for i in range(0, total_vectors, batch_size):
        # Fetch batch logic here
        pass
    
    # Save backup
    with open(backup_path, 'w') as f:
        json.dump(backup_data, f)
    
    return backup_path
```

### 5.3 Recovery Procedures
```bash
#!/bin/bash
# restore_neo4j.sh

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: ./restore_neo4j.sh <backup_file>"
    exit 1
fi

# Stop Neo4j
sudo systemctl stop neo4j

# Extract backup
echo "Extracting backup..."
tar -xzf $BACKUP_FILE -C /

# Set permissions
chown -R neo4j:neo4j /var/lib/neo4j/data/

# Start Neo4j
sudo systemctl start neo4j

echo "Restore completed. Verify database integrity."
```

## 6. Performance Monitoring

### 6.1 Neo4j Performance Queries
```cypher
// Query performance metrics
CALL dbms.listQueries() YIELD queryId, username, query, elapsedTimeMillis
WHERE elapsedTimeMillis > 1000
RETURN queryId, username, query, elapsedTimeMillis
ORDER BY elapsedTimeMillis DESC;

// Memory usage
CALL dbms.queryJmx('org.neo4j:instance=kernel#0,name=*Memory*') 
YIELD name, attributes
RETURN name, attributes;

// Transaction metrics
CALL dbms.queryJmx('org.neo4j:instance=kernel#0,name=Transactions') 
YIELD attributes
RETURN attributes;
```

### 6.2 System Monitoring Script
```python
# monitor_system.py
import psutil
import time
from datetime import datetime

class SystemMonitor:
    def __init__(self):
        self.metrics = []
    
    def collect_metrics(self):
        """Collect system metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'used': psutil.virtual_memory().used,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent
            },
            'neo4j_process': self.check_process('neo4j'),
            'api_process': self.check_process('seldon-api')
        }
        
        self.metrics.append(metrics)
        return metrics
    
    def check_process(self, process_name):
        """Check if process is running and get stats"""
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            if process_name in proc.info['name']:
                return {
                    'running': True,
                    'pid': proc.info['pid'],
                    'cpu': proc.info['cpu_percent'],
                    'memory': proc.info['memory_percent']
                }
        return {'running': False}
    
    def alert_if_needed(self, metrics):
        """Send alerts for critical conditions"""
        if metrics['cpu_percent'] > 90:
            self.send_alert("CPU usage critical: {}%".format(metrics['cpu_percent']))
        
        if metrics['memory']['percent'] > 85:
            self.send_alert("Memory usage critical: {}%".format(metrics['memory']['percent']))
        
        if not metrics['neo4j_process']['running']:
            self.send_alert("Neo4j process is DOWN!")
```

### 6.3 Performance Dashboard
```bash
#!/bin/bash
# performance_dashboard.sh

while true; do
    clear
    echo "=== Project Seldon Performance Dashboard ==="
    echo "Time: $(date)"
    echo ""
    
    # CPU and Memory
    echo "=== System Resources ==="
    top -bn1 | head -5
    echo ""
    
    # Neo4j Status
    echo "=== Neo4j Status ==="
    systemctl status neo4j --no-pager | grep -E "(Active|Memory|CPU)"
    echo ""
    
    # API Health
    echo "=== API Health ==="
    curl -s http://localhost:8080/metrics | jq '.health'
    echo ""
    
    # Recent Errors
    echo "=== Recent Errors (Last 10) ==="
    journalctl -u neo4j -u seldon-api --since "1 hour ago" | grep ERROR | tail -10
    
    sleep 5
done
```

## 7. Troubleshooting Guide

### 7.1 Common Neo4j Issues

#### Issue: Neo4j Won't Start
```bash
# Check logs
sudo journalctl -u neo4j -n 100

# Common fixes:
# 1. Check disk space
df -h

# 2. Check permissions
ls -la /var/lib/neo4j/data/

# 3. Verify Java version
java -version

# 4. Check port conflicts
sudo netstat -tlnp | grep -E "(7474|7687)"
```

#### Issue: Slow Queries
```cypher
// Identify slow queries
CALL dbms.listQueries() 
YIELD queryId, username, query, elapsedTimeMillis
WHERE elapsedTimeMillis > 5000
RETURN *;

// Kill slow query
CALL dbms.killQuery('query-id-here');

// Add missing indexes
CREATE INDEX ON :Prospect(id);
CREATE INDEX ON :Theme(name);
CREATE INDEX ON :Sector(name);
```

### 7.2 Pinecone Issues

#### Issue: Connection Errors
```python
# debug_pinecone.py
import pinecone
import logging

logging.basicConfig(level=logging.DEBUG)

try:
    pinecone.init(
        api_key='your-api-key',
        environment='your-environment'
    )
    print("Connection successful")
    print(f"Indexes: {pinecone.list_indexes()}")
except Exception as e:
    print(f"Connection failed: {e}")
    # Check API key and environment
```

#### Issue: Query Performance
```python
# optimize_queries.py
def optimize_pinecone_query(index_name):
    index = pinecone.Index(index_name)
    
    # Use metadata filtering
    results = index.query(
        vector=[0.1] * 1536,
        top_k=10,
        include_metadata=True,
        filter={
            "sector": {"$in": ["energy", "manufacturing"]},
            "theme": "ransomware"
        }
    )
    
    # Batch queries for efficiency
    batch_queries = [
        {"vector": v, "top_k": 5, "filter": f}
        for v, f in query_pairs
    ]
    
    return index.query(queries=batch_queries)
```

### 7.3 API Issues

#### Issue: High Latency
```bash
# Diagnose API latency
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080/api/health

# curl-format.txt:
time_namelookup:  %{time_namelookup}\n
time_connect:  %{time_connect}\n
time_appconnect:  %{time_appconnect}\n
time_pretransfer:  %{time_pretransfer}\n
time_redirect:  %{time_redirect}\n
time_starttransfer:  %{time_starttransfer}\n
time_total:  %{time_total}\n
```

## 8. Security Best Practices

### 8.1 Access Control
```bash
# Configure firewall
sudo ufw allow from 10.0.0.0/24 to any port 7474  # Neo4j HTTP
sudo ufw allow from 10.0.0.0/24 to any port 7687  # Neo4j Bolt
sudo ufw allow from 10.0.0.0/24 to any port 8080  # API

# Enable SSL for Neo4j
# In neo4j.conf:
dbms.connector.https.enabled=true
dbms.ssl.policy.https.enabled=true
dbms.ssl.policy.https.base_directory=certificates/https
dbms.ssl.policy.https.private_key=private.key
dbms.ssl.policy.https.public_certificate=public.crt
```

### 8.2 Audit Logging
```cypher
// Enable query logging
CALL dbms.setConfigValue('dbms.logs.query.enabled', 'true');
CALL dbms.setConfigValue('dbms.logs.query.threshold', '0');

// Review security events
CALL dbms.security.listUsers();
CALL dbms.security.listRoles();
```

### 8.3 Security Checklist
```bash
#!/bin/bash
# security_audit.sh

echo "=== Security Audit Checklist ==="

# 1. Check for default passwords
echo -n "[ ] Default passwords changed: "
# Implementation here

# 2. SSL/TLS enabled
echo -n "[ ] SSL/TLS enabled: "
openssl s_client -connect localhost:7473 </dev/null 2>/dev/null | grep -q "SSL" && echo "YES" || echo "NO"

# 3. Firewall rules
echo -n "[ ] Firewall configured: "
sudo ufw status | grep -q "Status: active" && echo "YES" || echo "NO"

# 4. Latest patches
echo -n "[ ] System updated: "
apt list --upgradable 2>/dev/null | grep -q "upgradable" && echo "NO - Updates available" || echo "YES"

# 5. Backup encryption
echo -n "[ ] Backups encrypted: "
# Check backup encryption status

echo "=== Audit Complete ==="
```

## 9. Integration Management

### 9.1 MCP Server Management
```json
// mcp_config.json
{
  "servers": {
    "tavily": {
      "command": "npx",
      "args": ["@tavily/mcp-server"],
      "env": {
        "TAVILY_API_KEY": "${TAVILY_API_KEY}"
      },
      "health_check": "http://localhost:3001/health"
    },
    "brave": {
      "command": "npx",
      "args": ["@brave/mcp-server"],
      "env": {
        "BRAVE_API_KEY": "${BRAVE_API_KEY}"
      },
      "health_check": "http://localhost:3002/health"
    }
  }
}
```

### 9.2 API Gateway Configuration
```nginx
# nginx.conf for API Gateway
upstream neo4j_backend {
    server localhost:7474;
}

upstream api_backend {
    server localhost:8080;
}

server {
    listen 443 ssl;
    server_name seldon.company.com;
    
    ssl_certificate /etc/ssl/certs/seldon.crt;
    ssl_certificate_key /etc/ssl/private/seldon.key;
    
    location /neo4j/ {
        proxy_pass http://neo4j_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /api/ {
        proxy_pass http://api_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # Rate limiting
        limit_req zone=api_limit burst=20 nodelay;
    }
}
```

### 9.3 Integration Health Checks
```python
# check_integrations.py
import requests
import time

class IntegrationChecker:
    def __init__(self):
        self.endpoints = {
            'neo4j': 'http://localhost:7474/db/data/',
            'api': 'http://localhost:8080/health',
            'tavily': 'http://localhost:3001/health',
            'brave': 'http://localhost:3002/health'
        }
    
    def check_all(self):
        """Check all integration endpoints"""
        results = {}
        
        for name, url in self.endpoints.items():
            try:
                start = time.time()
                response = requests.get(url, timeout=5)
                elapsed = time.time() - start
                
                results[name] = {
                    'status': 'UP' if response.status_code == 200 else 'DOWN',
                    'response_time': elapsed,
                    'status_code': response.status_code
                }
            except Exception as e:
                results[name] = {
                    'status': 'DOWN',
                    'error': str(e)
                }
        
        return results
```

## 10. Data Quality Assurance

### 10.1 Data Validation Queries
```cypher
// Check for orphaned nodes
MATCH (n)
WHERE NOT (n)--()
RETURN labels(n) AS type, count(n) AS orphaned_count;

// Check for duplicate prospects
MATCH (p:Prospect)
WITH p.name AS name, count(*) AS count
WHERE count > 1
RETURN name, count
ORDER BY count DESC;

// Validate required properties
MATCH (p:Prospect)
WHERE p.id IS NULL OR p.name IS NULL OR p.sector IS NULL
RETURN p.id, p.name, p.sector
LIMIT 100;

// Check relationship integrity
MATCH (p:Prospect)-[r:HAS_THEME]->(t:Theme)
WHERE t.name IS NULL
RETURN p.name, type(r), t;
```

### 10.2 Data Quality Metrics
```python
# data_quality_metrics.py
from neo4j import GraphDatabase

class DataQualityChecker:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def check_completeness(self):
        """Check data completeness"""
        with self.driver.session() as session:
            # Check prospect completeness
            result = session.run("""
                MATCH (p:Prospect)
                RETURN 
                    count(p) AS total,
                    count(p.sector) AS with_sector,
                    count(p.executive_name) AS with_executive,
                    count(p.contact_email) AS with_email
            """)
            
            record = result.single()
            completeness = {
                'total_prospects': record['total'],
                'sector_coverage': record['with_sector'] / record['total'] * 100,
                'executive_coverage': record['with_executive'] / record['total'] * 100,
                'email_coverage': record['with_email'] / record['total'] * 100
            }
            
            return completeness
    
    def check_consistency(self):
        """Check data consistency"""
        queries = {
            'invalid_sectors': """
                MATCH (p:Prospect)
                WHERE p.sector NOT IN ['energy', 'manufacturing', 'utilities', 'transportation']
                RETURN count(p) AS count
            """,
            'invalid_themes': """
                MATCH (t:Theme)
                WHERE t.name NOT IN ['ransomware', 'supply_chain', 'insider_threat', 'itc_convergence']
                RETURN count(t) AS count
            """
        }
        
        results = {}
        with self.driver.session() as session:
            for check, query in queries.items():
                result = session.run(query)
                results[check] = result.single()['count']
        
        return results
```

### 10.3 Automated Data Cleaning
```bash
#!/bin/bash
# data_cleaning.sh

echo "=== Running Data Quality Checks ==="

# Run Neo4j data quality checks
cypher-shell -u neo4j -p $NEO4J_PASSWORD < data_quality_checks.cypher

# Run Python validation
python3 /opt/seldon/scripts/data_quality_metrics.py

# Clean orphaned nodes
cypher-shell -u neo4j -p $NEO4J_PASSWORD \
    "MATCH (n) WHERE NOT (n)--() DELETE n;"

# Update statistics
cypher-shell -u neo4j -p $NEO4J_PASSWORD \
    "CALL db.stats.clear(); CALL db.stats.collect();"

echo "=== Data Cleaning Complete ==="
```

## 11. Emergency Response

### 11.1 Emergency Contacts
```yaml
# emergency_contacts.yaml
oncall:
  primary:
    name: "System Administrator"
    phone: "+1-555-0100"
    email: "sysadmin@company.com"
  secondary:
    name: "Database Administrator"
    phone: "+1-555-0101"
    email: "dba@company.com"
  escalation:
    name: "IT Manager"
    phone: "+1-555-0102"
    email: "it-manager@company.com"

vendors:
  neo4j:
    support: "support@neo4j.com"
    phone: "+1-855-636-4532"
  pinecone:
    support: "support@pinecone.io"
```

### 11.2 Emergency Procedures

#### System Down
```bash
#!/bin/bash
# emergency_recovery.sh

echo "=== EMERGENCY RECOVERY INITIATED ==="
echo "Time: $(date)"

# 1. Capture current state
echo "Capturing system state..."
ps aux > /tmp/emergency_ps.log
df -h > /tmp/emergency_df.log
free -m > /tmp/emergency_mem.log

# 2. Attempt service restart
echo "Attempting service restart..."
sudo systemctl restart neo4j
sleep 10
sudo systemctl restart seldon-api

# 3. Check if services are up
if systemctl is-active --quiet neo4j; then
    echo "Neo4j: RECOVERED"
else
    echo "Neo4j: STILL DOWN - Escalating..."
    # Send alert
fi

# 4. Run diagnostics
/opt/seldon/scripts/diagnostics.sh > /tmp/emergency_diagnostics.log

# 5. Failover if needed
if [ "$1" == "--failover" ]; then
    echo "Initiating failover to backup system..."
    /opt/seldon/scripts/failover.sh
fi

echo "=== Recovery attempt complete. Check logs for details. ==="
```

#### Data Corruption
```cypher
// Emergency data integrity check
CALL dbms.checkConsistency() 
YIELD report, success
RETURN success, report;

// If corruption detected, restore from backup
// See Section 5.3 for restore procedures
```

#### Security Breach
```bash
#!/bin/bash
# security_incident_response.sh

echo "=== SECURITY INCIDENT RESPONSE ==="

# 1. Isolate system
echo "Isolating system..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw enable

# 2. Capture evidence
echo "Capturing evidence..."
mkdir -p /secure/incident_$(date +%Y%m%d_%H%M%S)
cp -r /var/log/* /secure/incident_*/
netstat -an > /secure/incident_*/network_connections.txt
ps auxf > /secure/incident_*/processes.txt

# 3. Reset credentials
echo "Resetting all credentials..."
# Neo4j passwords
cypher-shell -u neo4j -p $OLD_PASSWORD \
    "ALTER CURRENT USER SET PASSWORD FROM '$OLD_PASSWORD' TO '$NEW_PASSWORD';"

# 4. Notify security team
echo "Sending security alert..."
# Alert implementation

echo "=== Initial response complete. Await security team instructions. ==="
```

### 11.3 Disaster Recovery Plan
```yaml
# disaster_recovery_plan.yaml
recovery_objectives:
  rpo: "4 hours"  # Recovery Point Objective
  rto: "2 hours"  # Recovery Time Objective

recovery_steps:
  1_assess:
    - "Determine extent of failure"
    - "Check backup availability"
    - "Notify stakeholders"
  
  2_prepare:
    - "Provision replacement infrastructure"
    - "Verify network connectivity"
    - "Prepare recovery scripts"
  
  3_restore:
    - "Restore Neo4j from backup"
    - "Restore Pinecone data"
    - "Restore configuration files"
  
  4_validate:
    - "Run data integrity checks"
    - "Verify API endpoints"
    - "Test critical queries"
  
  5_cutover:
    - "Update DNS/load balancer"
    - "Monitor system health"
    - "Document incident"
```

## Appendices

### A. Useful Commands Reference
```bash
# Neo4j
neo4j-admin dump --database=neo4j --to=/backup/neo4j.dump
neo4j-admin load --from=/backup/neo4j.dump --database=neo4j

# System monitoring
htop  # Interactive process viewer
iotop  # I/O monitoring
nethogs  # Network traffic by process

# Log analysis
grep -E "ERROR|WARN" /var/log/neo4j/*.log | tail -50
journalctl -u seldon-api --since "1 hour ago" | grep -v INFO
```

### B. Configuration Templates
Available in `/opt/seldon/templates/`:
- `neo4j.conf.template`
- `nginx.conf.template`
- `systemd.service.template`

### C. Automation Scripts
All scripts mentioned in this guide are available in:
`/opt/seldon/scripts/admin/`

---

**Document Maintenance**: This guide should be reviewed and updated quarterly or after any major system changes. Last review: December 6, 2025