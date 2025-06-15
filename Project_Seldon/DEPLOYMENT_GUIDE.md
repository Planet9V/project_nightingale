# Project Seldon - Deployment Guide

## Overview

This guide covers deploying Project Seldon to production environments, including infrastructure setup, security configuration, monitoring, and maintenance procedures.

## Table of Contents

1. [Infrastructure Requirements](#infrastructure-requirements)
2. [Pre-Deployment Checklist](#pre-deployment-checklist)
3. [Cloud Deployment](#cloud-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Database Setup](#database-setup)
6. [Security Configuration](#security-configuration)
7. [Monitoring & Observability](#monitoring--observability)
8. [Backup & Recovery](#backup--recovery)
9. [Performance Tuning](#performance-tuning)
10. [Troubleshooting](#troubleshooting)

## Infrastructure Requirements

### Minimum Requirements (Small Deployment)
- **Compute**: 8 vCPUs, 32GB RAM
- **Storage**: 500GB SSD
- **Network**: 1Gbps connection
- **Databases**: 
  - Neo4j: 4 vCPUs, 16GB RAM
  - PostgreSQL: 2 vCPUs, 8GB RAM

### Recommended Production Setup
- **Compute**: 16+ vCPUs, 64GB+ RAM per service
- **Storage**: 2TB+ NVMe SSD with backup
- **Network**: 10Gbps connection
- **Load Balancer**: Application load balancer
- **CDN**: For static assets and reports

### Cloud Provider Requirements

#### AWS
```yaml
# Recommended instance types
Intelligence Engine: c5.2xlarge
EAB Generator: c5.xlarge
Report Generator: c5.xlarge
Neo4j: r5.2xlarge
PostgreSQL: db.r5.xlarge (RDS)
```

#### Azure
```yaml
# Recommended instance types
Intelligence Engine: Standard_D8s_v3
EAB Generator: Standard_D4s_v3
Report Generator: Standard_D4s_v3
Neo4j: Standard_E8s_v3
PostgreSQL: GP_Gen5_8 (Azure Database)
```

#### GCP
```yaml
# Recommended instance types
Intelligence Engine: n2-standard-8
EAB Generator: n2-standard-4
Report Generator: n2-standard-4
Neo4j: n2-highmem-8
PostgreSQL: db-n1-standard-4 (Cloud SQL)
```

## Pre-Deployment Checklist

### Environment Variables
```bash
# Create production .env file
cat > .env.production << EOF
# Application
NODE_ENV=production
LOG_LEVEL=info

# Services
INTELLIGENCE_ENGINE_URL=https://intelligence.seldon.company.com
EAB_GENERATOR_URL=https://eab.seldon.company.com
REPORT_GENERATOR_URL=https://reports.seldon.company.com

# Databases
NEO4J_URI=bolt://neo4j.internal:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=${NEO4J_PASSWORD}
POSTGRES_HOST=postgres.internal
POSTGRES_PORT=5432
POSTGRES_DB=project_seldon
POSTGRES_USER=seldon
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# External APIs
OPENAI_API_KEY=${OPENAI_API_KEY}
TAVILY_API_KEY=${TAVILY_API_KEY}
BRAVE_API_KEY=${BRAVE_API_KEY}
PINECONE_API_KEY=${PINECONE_API_KEY}
PINECONE_ENVIRONMENT=production

# Security
JWT_SECRET=${JWT_SECRET}
API_KEY_SALT=${API_KEY_SALT}
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# Monitoring
SENTRY_DSN=${SENTRY_DSN}
DATADOG_API_KEY=${DATADOG_API_KEY}
EOF
```

### SSL Certificates
```bash
# Generate certificates for internal communication
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout seldon-internal.key \
  -out seldon-internal.crt \
  -subj "/C=US/ST=State/L=City/O=Company/CN=*.seldon.internal"

# Store in secrets management
kubectl create secret tls seldon-internal-tls \
  --cert=seldon-internal.crt \
  --key=seldon-internal.key
```

### Database Migrations
```bash
# Run database migrations
npm run migrate:production

# Verify migrations
psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB \
  -c "SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 5;"
```

## Cloud Deployment

### AWS Deployment with Terraform

```hcl
# deployment/terraform/aws/main.tf
provider "aws" {
  region = var.aws_region
}

# VPC Configuration
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"

  name = "seldon-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = true
  enable_dns_hostnames = true

  tags = {
    Project = "Seldon"
    Environment = "production"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "seldon" {
  name = "seldon-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Application Load Balancer
resource "aws_lb" "seldon" {
  name               = "seldon-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = true
  enable_http2              = true

  tags = {
    Project = "Seldon"
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "postgres" {
  identifier = "seldon-postgres"
  
  engine         = "postgres"
  engine_version = "14.7"
  instance_class = "db.r5.xlarge"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_encrypted     = true
  
  db_name  = "project_seldon"
  username = var.db_username
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.postgres.id]
  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  tags = {
    Project = "Seldon"
  }
}
```

### Deploy Script
```bash
#!/bin/bash
# deployment/scripts/deploy.sh

set -e

ENVIRONMENT=${1:-production}
VERSION=${2:-latest}

echo "Deploying Project Seldon ${VERSION} to ${ENVIRONMENT}"

# Build Docker images
docker build -t seldon/intelligence:${VERSION} -f deployment/docker/intelligence.Dockerfile .
docker build -t seldon/eab:${VERSION} -f deployment/docker/eab.Dockerfile .
docker build -t seldon/reports:${VERSION} -f deployment/docker/reports.Dockerfile .

# Push to registry
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ${ECR_REGISTRY}
docker push ${ECR_REGISTRY}/seldon/intelligence:${VERSION}
docker push ${ECR_REGISTRY}/seldon/eab:${VERSION}
docker push ${ECR_REGISTRY}/seldon/reports:${VERSION}

# Update services
aws ecs update-service --cluster seldon-cluster --service intelligence-engine --force-new-deployment
aws ecs update-service --cluster seldon-cluster --service eab-generator --force-new-deployment
aws ecs update-service --cluster seldon-cluster --service report-generator --force-new-deployment

echo "Deployment complete!"
```

## Kubernetes Deployment

### Namespace and RBAC
```yaml
# deployment/kubernetes/00-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: project-seldon
  labels:
    name: project-seldon
    
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: seldon-service-account
  namespace: project-seldon

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: project-seldon
  name: seldon-role
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
```

### ConfigMaps and Secrets
```yaml
# deployment/kubernetes/01-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: seldon-config
  namespace: project-seldon
data:
  NODE_ENV: "production"
  LOG_LEVEL: "info"
  NEO4J_URI: "bolt://neo4j-service:7687"
  POSTGRES_HOST: "postgres-service"
  POSTGRES_PORT: "5432"
  POSTGRES_DB: "project_seldon"

---
apiVersion: v1
kind: Secret
metadata:
  name: seldon-secrets
  namespace: project-seldon
type: Opaque
stringData:
  NEO4J_PASSWORD: "${NEO4J_PASSWORD}"
  POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"
  JWT_SECRET: "${JWT_SECRET}"
  OPENAI_API_KEY: "${OPENAI_API_KEY}"
  TAVILY_API_KEY: "${TAVILY_API_KEY}"
  BRAVE_API_KEY: "${BRAVE_API_KEY}"
  PINECONE_API_KEY: "${PINECONE_API_KEY}"
```

### Service Deployments
```yaml
# deployment/kubernetes/02-intelligence-engine.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: intelligence-engine
  namespace: project-seldon
  labels:
    app: intelligence-engine
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: intelligence-engine
  template:
    metadata:
      labels:
        app: intelligence-engine
        version: v1
    spec:
      serviceAccountName: seldon-service-account
      containers:
      - name: intelligence-engine
        image: seldon/intelligence:latest
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: NODE_ENV
          valueFrom:
            configMapKeyRef:
              name: seldon-config
              key: NODE_ENV
        envFrom:
        - configMapRef:
            name: seldon-config
        - secretRef:
            name: seldon-secrets
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: cache
        emptyDir:
          sizeLimit: 10Gi

---
apiVersion: v1
kind: Service
metadata:
  name: intelligence-engine-service
  namespace: project-seldon
spec:
  selector:
    app: intelligence-engine
  ports:
  - name: http
    port: 8000
    targetPort: 8000
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP
```

### Ingress Configuration
```yaml
# deployment/kubernetes/03-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: seldon-ingress
  namespace: project-seldon
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.seldon.company.com
    secretName: seldon-tls
  rules:
  - host: api.seldon.company.com
    http:
      paths:
      - path: /v1/intelligence
        pathType: Prefix
        backend:
          service:
            name: intelligence-engine-service
            port:
              number: 8000
      - path: /v1/eab
        pathType: Prefix
        backend:
          service:
            name: eab-generator-service
            port:
              number: 8001
      - path: /v1/reports
        pathType: Prefix
        backend:
          service:
            name: report-generator-service
            port:
              number: 8002
```

### Horizontal Pod Autoscaling
```yaml
# deployment/kubernetes/04-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: intelligence-engine-hpa
  namespace: project-seldon
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: intelligence-engine
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

## Database Setup

### Neo4j Production Configuration
```yaml
# deployment/neo4j/neo4j.conf
# Memory configuration
dbms.memory.heap.initial_size=8g
dbms.memory.heap.max_size=8g
dbms.memory.pagecache.size=10g

# Performance
dbms.threads.worker_count=20
dbms.connector.bolt.thread_pool_max_size=400
dbms.transaction.timeout=5m

# Security
dbms.security.auth_enabled=true
dbms.security.procedures.unrestricted=algo.*,apoc.*
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.bolt.base_directory=certificates
dbms.ssl.policy.bolt.private_key=private.key
dbms.ssl.policy.bolt.public_certificate=public.crt

# Backups
dbms.backup.enabled=true
dbms.backup.incremental.strategy=VOLUME
```

### PostgreSQL Production Tuning
```sql
-- Performance settings
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
ALTER SYSTEM SET work_mem = '256MB';
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET max_parallel_workers_per_gather = 4;
ALTER SYSTEM SET max_parallel_workers = 8;

-- Write performance
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET checkpoint_timeout = '30min';

-- Query optimization
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Apply changes
SELECT pg_reload_conf();
```

## Security Configuration

### Network Security
```yaml
# deployment/kubernetes/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: seldon-network-policy
  namespace: project-seldon
spec:
  podSelector:
    matchLabels:
      app: intelligence-engine
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: project-seldon
    - podSelector:
        matchLabels:
          app: nginx-ingress
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: project-seldon
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 7687
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443  # External APIs
```

### Pod Security Policy
```yaml
# deployment/kubernetes/pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: seldon-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

## Monitoring & Observability

### Prometheus Configuration
```yaml
# deployment/monitoring/prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    scrape_configs:
    - job_name: 'project-seldon'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['project-seldon']
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
```

### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "Project Seldon Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{job=\"project-seldon\"}[5m])) by (service)"
          }
        ]
      },
      {
        "title": "Response Time P95",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"project-seldon\"}[5m]))"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{job=\"project-seldon\",status=~\"5..\"}[5m])) by (service)"
          }
        ]
      }
    ]
  }
}
```

### Application Logging
```typescript
// src/utils/logger.ts
import winston from 'winston';
import { ElasticsearchTransport } from 'winston-elasticsearch';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: {
    service: process.env.SERVICE_NAME,
    version: process.env.APP_VERSION,
    environment: process.env.NODE_ENV
  },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new ElasticsearchTransport({
      level: 'info',
      clientOpts: {
        node: process.env.ELASTICSEARCH_URL,
        auth: {
          username: process.env.ELASTICSEARCH_USER,
          password: process.env.ELASTICSEARCH_PASS
        }
      },
      index: 'seldon-logs'
    })
  ]
});

// Structured logging middleware
export const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('HTTP Request', {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      requestId: req.id
    });
  });
  
  next();
};
```

## Backup & Recovery

### Automated Backup Script
```bash
#!/bin/bash
# deployment/scripts/backup.sh

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/${TIMESTAMP}"

echo "Starting backup at ${TIMESTAMP}"

# Create backup directory
mkdir -p ${BACKUP_DIR}

# Backup PostgreSQL
echo "Backing up PostgreSQL..."
PGPASSWORD=${POSTGRES_PASSWORD} pg_dump \
  -h ${POSTGRES_HOST} \
  -U ${POSTGRES_USER} \
  -d ${POSTGRES_DB} \
  -f ${BACKUP_DIR}/postgres_backup.sql

# Backup Neo4j
echo "Backing up Neo4j..."
docker exec neo4j-container \
  neo4j-admin backup \
  --database=neo4j \
  --to=/backups/neo4j_${TIMESTAMP}.backup

# Backup application data
echo "Backing up application data..."
tar -czf ${BACKUP_DIR}/app_data.tar.gz /app/data

# Upload to S3
echo "Uploading to S3..."
aws s3 sync ${BACKUP_DIR} s3://seldon-backups/${TIMESTAMP}/

# Cleanup old backups (keep last 30 days)
find /backups -type d -mtime +30 -exec rm -rf {} \;

echo "Backup completed successfully"
```

### Disaster Recovery Plan
```yaml
# deployment/dr/recovery-plan.yaml
recovery_objectives:
  rpo: 4_hours  # Recovery Point Objective
  rto: 2_hours  # Recovery Time Objective

backup_schedule:
  databases:
    frequency: hourly
    retention: 168_hours  # 7 days
  
  application_data:
    frequency: daily
    retention: 30_days
  
  configuration:
    frequency: on_change
    retention: indefinite

recovery_procedures:
  - step: 1
    name: "Assess Damage"
    tasks:
      - Identify affected components
      - Determine data loss window
      - Activate incident response team
  
  - step: 2
    name: "Restore Infrastructure"
    tasks:
      - Provision new infrastructure
      - Restore network configuration
      - Deploy base services
  
  - step: 3
    name: "Restore Data"
    tasks:
      - Restore PostgreSQL from backup
      - Restore Neo4j from backup
      - Verify data integrity
  
  - step: 4
    name: "Deploy Applications"
    tasks:
      - Deploy microservices
      - Restore configuration
      - Run smoke tests
  
  - step: 5
    name: "Validation"
    tasks:
      - Execute integration tests
      - Verify API functionality
      - Monitor for errors
```

## Performance Tuning

### Application Performance
```typescript
// Performance optimizations
import { LRUCache } from 'lru-cache';
import { Pool } from 'pg';

// Connection pooling
export const pgPool = new Pool({
  host: process.env.POSTGRES_HOST,
  port: parseInt(process.env.POSTGRES_PORT),
  database: process.env.POSTGRES_DB,
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Response caching
export const cache = new LRUCache({
  max: 500,
  ttl: 1000 * 60 * 5, // 5 minutes
  updateAgeOnGet: true,
  updateAgeOnHas: true,
});

// Middleware for caching
export const cacheMiddleware = (duration = 300) => {
  return (req, res, next) => {
    const key = `${req.method}:${req.url}`;
    const cached = cache.get(key);
    
    if (cached) {
      return res.json(cached);
    }
    
    const originalJson = res.json;
    res.json = function(data) {
      cache.set(key, data);
      originalJson.call(this, data);
    };
    
    next();
  };
};
```

### Database Query Optimization
```sql
-- Create optimized indexes
CREATE INDEX CONCURRENTLY idx_prospects_sector_theme 
ON prospects(sector, theme) 
WHERE deleted_at IS NULL;

CREATE INDEX CONCURRENTLY idx_threats_actor_date 
ON threats(actor_id, detection_date DESC) 
WHERE active = true;

CREATE INDEX CONCURRENTLY idx_vulnerabilities_cvss_exploited 
ON vulnerabilities(cvss_score DESC) 
WHERE exploit_available = true;

-- Materialized views for complex queries
CREATE MATERIALIZED VIEW mv_threat_summary AS
SELECT 
  p.sector,
  p.theme,
  COUNT(DISTINCT t.actor_id) as threat_actor_count,
  AVG(t.sophistication_score) as avg_sophistication,
  MAX(t.last_seen) as most_recent_activity
FROM prospects p
JOIN prospect_threats pt ON p.id = pt.prospect_id
JOIN threats t ON pt.threat_id = t.id
WHERE p.deleted_at IS NULL
GROUP BY p.sector, p.theme;

CREATE INDEX ON mv_threat_summary(sector, theme);

-- Refresh materialized view
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_summary;
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Service Won't Start
```bash
# Check logs
kubectl logs -n project-seldon deployment/intelligence-engine --tail=100

# Check resource constraints
kubectl describe pod -n project-seldon -l app=intelligence-engine

# Verify environment variables
kubectl exec -n project-seldon deployment/intelligence-engine -- env | grep -E "(NEO4J|POSTGRES|API)"
```

#### 2. Database Connection Issues
```bash
# Test Neo4j connection
kubectl run -it --rm neo4j-test --image=neo4j:5 --restart=Never -- \
  cypher-shell -a bolt://neo4j-service:7687 -u neo4j -p $NEO4J_PASSWORD \
  "MATCH (n) RETURN count(n) LIMIT 1;"

# Test PostgreSQL connection
kubectl run -it --rm psql-test --image=postgres:14 --restart=Never -- \
  psql -h postgres-service -U seldon -d project_seldon -c "SELECT version();"
```

#### 3. Performance Issues
```bash
# Check CPU and memory usage
kubectl top pods -n project-seldon

# Analyze slow queries (PostgreSQL)
kubectl exec -n project-seldon postgres-0 -- \
  psql -U seldon -d project_seldon -c \
  "SELECT query, calls, mean_time, max_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"

# Check Neo4j query performance
kubectl exec -n project-seldon neo4j-0 -- \
  cypher-shell -u neo4j -p $NEO4J_PASSWORD \
  "CALL dbms.listQueries() YIELD query, elapsedTimeMillis WHERE elapsedTimeMillis > 1000 RETURN query, elapsedTimeMillis;"
```

#### 4. API Errors
```typescript
// Enhanced error handling
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    requestId: req.id
  });
  
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
  
  res.status(err.status || 500).json({
    success: false,
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message,
      requestId: req.id
    }
  });
});
```

### Health Check Endpoints
```typescript
// Comprehensive health check
app.get('/health/detailed', async (req, res) => {
  const checks = {
    service: 'healthy',
    postgres: 'unknown',
    neo4j: 'unknown',
    pinecone: 'unknown',
    redis: 'unknown'
  };
  
  try {
    // Check PostgreSQL
    await pgPool.query('SELECT 1');
    checks.postgres = 'healthy';
  } catch (err) {
    checks.postgres = 'unhealthy';
  }
  
  try {
    // Check Neo4j
    await neo4jDriver.verifyConnectivity();
    checks.neo4j = 'healthy';
  } catch (err) {
    checks.neo4j = 'unhealthy';
  }
  
  try {
    // Check Pinecone
    await pinecone.Index('seldon-intelligence').describeIndexStats();
    checks.pinecone = 'healthy';
  } catch (err) {
    checks.pinecone = 'unhealthy';
  }
  
  const allHealthy = Object.values(checks).every(status => status === 'healthy');
  
  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'healthy' : 'degraded',
    checks,
    timestamp: new Date().toISOString()
  });
});
```

## Post-Deployment Verification

### Smoke Tests
```bash
#!/bin/bash
# deployment/scripts/smoke-tests.sh

API_URL=${1:-https://api.seldon.company.com}

echo "Running smoke tests against ${API_URL}"

# Test health endpoints
echo "Testing health endpoints..."
curl -f ${API_URL}/v1/intelligence/health || exit 1
curl -f ${API_URL}/v1/eab/health || exit 1
curl -f ${API_URL}/v1/reports/health || exit 1

# Test authentication
echo "Testing authentication..."
TOKEN=$(curl -X POST ${API_URL}/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"apiKey":"'${API_KEY}'"}' | jq -r '.token')

# Test core functionality
echo "Testing intelligence analysis..."
curl -f -X POST ${API_URL}/v1/intelligence/analyze \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "prospect": "Test Company",
    "analysisType": "quick"
  }' || exit 1

echo "All smoke tests passed!"
```

### Load Testing
```yaml
# deployment/tests/k6-load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },  // Ramp up
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '2m', target: 200 },  // Ramp up to 200
    { duration: '5m', target: 200 },  // Stay at 200 users
    { duration: '2m', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.1'],    // Error rate under 10%
  },
};

export default function() {
  const params = {
    headers: {
      'Authorization': `Bearer ${__ENV.API_TOKEN}`,
      'Content-Type': 'application/json',
    },
  };
  
  const response = http.post(
    `${__ENV.API_URL}/v1/intelligence/analyze`,
    JSON.stringify({
      prospect: 'Load Test Company',
      analysisType: 'quick'
    }),
    params
  );
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  sleep(1);
}
```

## Maintenance Procedures

### Rolling Updates
```bash
#!/bin/bash
# deployment/scripts/rolling-update.sh

SERVICE=$1
VERSION=$2

echo "Performing rolling update of ${SERVICE} to version ${VERSION}"

# Update image
kubectl set image deployment/${SERVICE} ${SERVICE}=seldon/${SERVICE}:${VERSION} \
  -n project-seldon

# Wait for rollout
kubectl rollout status deployment/${SERVICE} -n project-seldon

# Verify
kubectl get pods -n project-seldon -l app=${SERVICE}
```

### Database Maintenance
```sql
-- Weekly maintenance tasks
-- Run during maintenance window

-- Update statistics
ANALYZE;

-- Reindex if needed
REINDEX DATABASE project_seldon;

-- Clean up old data
DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days';
DELETE FROM api_logs WHERE created_at < NOW() - INTERVAL '30 days';

-- Vacuum to reclaim space
VACUUM ANALYZE;
```

---

## Support Resources

- **Documentation**: Internal wiki at `https://wiki.company.com/project-seldon`
- **Monitoring**: `https://grafana.company.com/d/seldon-overview`
- **Logs**: `https://kibana.company.com/app/discover#/seldon-*`
- **On-Call**: PagerDuty integration configured
- **Slack**: `#project-seldon-ops` channel

For production issues, follow the incident response procedure in the runbook.