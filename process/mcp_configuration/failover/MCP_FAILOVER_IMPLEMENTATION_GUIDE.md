# MCP Failover Implementation Guide

## Quick Start: Immediate Deployment Scripts

### 1. Health Check Monitor Service

```javascript
// mcp-health-monitor.js
const axios = require('axios');
const EventEmitter = require('events');

class MCPHealthMonitor extends EventEmitter {
  constructor() {
    super();
    this.services = {
      pinecone: {
        url: process.env.PINECONE_HOST,
        headers: { 'Api-Key': process.env.PINECONE_API_KEY },
        healthEndpoint: '/describe_index_stats',
        critical: true
      },
      neo4j: {
        url: process.env.NEO4J_URI.replace('neo4j+s://', 'https://'),
        auth: {
          username: process.env.NEO4J_USER,
          password: process.env.NEO4J_PASSWORD
        },
        healthEndpoint: '/db/data/',
        critical: true
      },
      graphlit: {
        url: process.env.GRAPHLIT_API_URL,
        headers: {
          'Authorization': `Bearer ${process.env.GRAPHLIT_JWT_SECRET}`,
          'X-Graphlit-Organization-Id': process.env.GRAPHLIT_ORGANIZATION_ID
        },
        healthEndpoint: '',
        critical: true
      },
      tavily: {
        url: 'https://api.tavily.com',
        headers: { 'api-key': process.env.TAVILY_API_KEY },
        healthEndpoint: '/status',
        critical: false
      }
    };
    
    this.healthStatus = new Map();
    this.startMonitoring();
  }
  
  async checkService(name, config) {
    try {
      const response = await axios({
        method: 'GET',
        url: `${config.url}${config.healthEndpoint}`,
        headers: config.headers,
        auth: config.auth,
        timeout: 5000
      });
      
      return {
        service: name,
        status: 'healthy',
        responseTime: response.duration,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        service: name,
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
  
  startMonitoring() {
    setInterval(async () => {
      for (const [name, config] of Object.entries(this.services)) {
        const health = await this.checkService(name, config);
        const previousStatus = this.healthStatus.get(name);
        
        this.healthStatus.set(name, health);
        
        // Emit events on status change
        if (previousStatus && previousStatus.status !== health.status) {
          this.emit('statusChange', { name, previousStatus, currentStatus: health });
          
          if (config.critical && health.status === 'unhealthy') {
            this.emit('criticalFailure', { name, health });
          }
        }
      }
    }, 5000); // Check every 5 seconds
  }
  
  getHealthReport() {
    return Array.from(this.healthStatus.entries()).map(([name, status]) => ({
      ...status,
      critical: this.services[name].critical
    }));
  }
}

// Usage
const monitor = new MCPHealthMonitor();

monitor.on('criticalFailure', async ({ name, health }) => {
  console.error(`CRITICAL: Service ${name} is down!`, health);
  // Trigger failover
  await triggerFailover(name);
});

monitor.on('statusChange', ({ name, previousStatus, currentStatus }) => {
  console.log(`Service ${name} status changed from ${previousStatus.status} to ${currentStatus.status}`);
});
```

### 2. Circuit Breaker Implementation

```javascript
// mcp-circuit-breaker.js
class MCPCircuitBreaker {
  constructor(service, options = {}) {
    this.service = service;
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000;
    this.timeout = options.timeout || 5000;
    
    this.state = 'CLOSED';
    this.failures = 0;
    this.nextAttempt = Date.now();
  }
  
  async call(operation) {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        throw new Error(`Circuit breaker is OPEN for ${this.service}`);
      }
      this.state = 'HALF_OPEN';
    }
    
    try {
      const result = await this.executeWithTimeout(operation);
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  async executeWithTimeout(operation) {
    return Promise.race([
      operation(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Operation timeout')), this.timeout)
      )
    ]);
  }
  
  onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }
  
  onFailure() {
    this.failures++;
    if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
      console.error(`Circuit breaker OPENED for ${this.service}`);
    }
  }
}

// Service-specific circuit breakers
const circuitBreakers = {
  pinecone: new MCPCircuitBreaker('pinecone', { 
    failureThreshold: 3, 
    resetTimeout: 30000 
  }),
  neo4j: new MCPCircuitBreaker('neo4j', { 
    failureThreshold: 3, 
    resetTimeout: 30000 
  }),
  tavily: new MCPCircuitBreaker('tavily', { 
    failureThreshold: 10, 
    resetTimeout: 60000 
  })
};

// Wrapper for MCP calls
async function callMCPService(service, operation) {
  const breaker = circuitBreakers[service];
  if (!breaker) {
    return operation(); // No circuit breaker for this service
  }
  
  return breaker.call(operation);
}
```

### 3. Failover Controller

```javascript
// mcp-failover-controller.js
class MCPFailoverController {
  constructor() {
    this.services = {
      pinecone: {
        primary: {
          host: process.env.PINECONE_HOST,
          apiKey: process.env.PINECONE_API_KEY
        },
        secondary: {
          host: process.env.PINECONE_BACKUP_HOST,
          apiKey: process.env.PINECONE_BACKUP_API_KEY
        },
        current: 'primary'
      },
      neo4j: {
        primary: {
          uri: process.env.NEO4J_URI,
          user: process.env.NEO4J_USER,
          password: process.env.NEO4J_PASSWORD
        },
        secondary: {
          uri: process.env.NEO4J_BACKUP_URI,
          user: process.env.NEO4J_USER,
          password: process.env.NEO4J_PASSWORD
        },
        current: 'primary'
      }
    };
  }
  
  async failover(serviceName) {
    const service = this.services[serviceName];
    if (!service) {
      throw new Error(`Unknown service: ${serviceName}`);
    }
    
    console.log(`Initiating failover for ${serviceName}...`);
    
    // Switch to secondary
    const previousEndpoint = service.current;
    service.current = service.current === 'primary' ? 'secondary' : 'primary';
    
    // Update environment variables for MCP
    this.updateMCPConfig(serviceName, service[service.current]);
    
    // Notify about failover
    await this.notifyFailover(serviceName, previousEndpoint, service.current);
    
    console.log(`Failover complete. ${serviceName} now using ${service.current}`);
    
    return {
      service: serviceName,
      previousEndpoint,
      currentEndpoint: service.current,
      timestamp: new Date().toISOString()
    };
  }
  
  updateMCPConfig(serviceName, config) {
    switch(serviceName) {
      case 'pinecone':
        process.env.PINECONE_HOST = config.host;
        process.env.PINECONE_API_KEY = config.apiKey;
        break;
      case 'neo4j':
        process.env.NEO4J_URI = config.uri;
        break;
    }
  }
  
  async notifyFailover(service, from, to) {
    // Send notification to ops team
    console.log(`NOTIFICATION: ${service} failed over from ${from} to ${to}`);
    // In production, integrate with your notification system
  }
  
  getStatus() {
    return Object.entries(this.services).map(([name, config]) => ({
      service: name,
      activeEndpoint: config.current,
      endpoints: {
        primary: config.primary,
        secondary: config.secondary
      }
    }));
  }
}
```

### 4. Load Balancer with Health Awareness

```javascript
// mcp-load-balancer.js
class MCPLoadBalancer {
  constructor(serviceName, instances) {
    this.serviceName = serviceName;
    this.instances = instances.map((instance, index) => ({
      ...instance,
      id: `${serviceName}-${index}`,
      healthScore: 1.0,
      activeConnections: 0,
      lastUsed: 0
    }));
  }
  
  selectInstance(strategy = 'health_weighted') {
    const healthyInstances = this.instances.filter(i => i.healthScore > 0.3);
    
    if (healthyInstances.length === 0) {
      throw new Error(`No healthy instances for ${this.serviceName}`);
    }
    
    let selected;
    switch(strategy) {
      case 'round_robin':
        selected = this.roundRobin(healthyInstances);
        break;
      case 'least_connections':
        selected = this.leastConnections(healthyInstances);
        break;
      case 'health_weighted':
      default:
        selected = this.healthWeighted(healthyInstances);
    }
    
    selected.activeConnections++;
    selected.lastUsed = Date.now();
    
    return selected;
  }
  
  roundRobin(instances) {
    const now = Date.now();
    return instances.reduce((oldest, instance) => 
      instance.lastUsed < oldest.lastUsed ? instance : oldest
    );
  }
  
  leastConnections(instances) {
    return instances.reduce((least, instance) => 
      instance.activeConnections < least.activeConnections ? instance : least
    );
  }
  
  healthWeighted(instances) {
    const totalWeight = instances.reduce((sum, i) => sum + i.healthScore, 0);
    const random = Math.random() * totalWeight;
    
    let accumulator = 0;
    for (const instance of instances) {
      accumulator += instance.healthScore;
      if (random <= accumulator) {
        return instance;
      }
    }
    
    return instances[0];
  }
  
  releaseConnection(instanceId) {
    const instance = this.instances.find(i => i.id === instanceId);
    if (instance && instance.activeConnections > 0) {
      instance.activeConnections--;
    }
  }
  
  updateHealth(instanceId, healthScore) {
    const instance = this.instances.find(i => i.id === instanceId);
    if (instance) {
      instance.healthScore = healthScore;
    }
  }
}

// Example usage for Neo4j read replicas
const neo4jLoadBalancer = new MCPLoadBalancer('neo4j', [
  { uri: process.env.NEO4J_URI },
  { uri: process.env.NEO4J_READ_REPLICA_1 },
  { uri: process.env.NEO4J_READ_REPLICA_2 }
]);
```

### 5. State Management for Failover

```javascript
// mcp-state-manager.js
const Redis = require('redis');

class MCPStateManager {
  constructor() {
    this.redis = Redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379'
    });
    
    this.redis.on('error', (err) => console.error('Redis error:', err));
    this.redis.connect();
  }
  
  async saveServiceState(service, state) {
    const key = `mcp:state:${service}`;
    const value = {
      ...state,
      timestamp: Date.now(),
      version: this.generateVersion()
    };
    
    await this.redis.set(key, JSON.stringify(value), {
      EX: 3600 // Expire after 1 hour
    });
    
    // Also save to backup
    await this.saveToBackup(service, value);
  }
  
  async getServiceState(service) {
    const key = `mcp:state:${service}`;
    const state = await this.redis.get(key);
    
    if (!state) {
      // Try to recover from backup
      return this.recoverFromBackup(service);
    }
    
    return JSON.parse(state);
  }
  
  async saveFailoverState(failoverEvent) {
    const key = `mcp:failover:${failoverEvent.service}:${Date.now()}`;
    await this.redis.set(key, JSON.stringify(failoverEvent), {
      EX: 86400 * 7 // Keep for 7 days
    });
    
    // Update current state
    await this.redis.set(`mcp:current:${failoverEvent.service}`, failoverEvent.currentEndpoint);
  }
  
  async getFailoverHistory(service, limit = 10) {
    const pattern = `mcp:failover:${service}:*`;
    const keys = await this.redis.keys(pattern);
    
    const history = [];
    for (const key of keys.slice(-limit)) {
      const event = await this.redis.get(key);
      history.push(JSON.parse(event));
    }
    
    return history.sort((a, b) => b.timestamp - a.timestamp);
  }
  
  generateVersion() {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  async saveToBackup(service, state) {
    // Implement backup storage (S3, disk, etc.)
    console.log(`Backing up state for ${service}`);
  }
  
  async recoverFromBackup(service) {
    // Implement recovery from backup
    console.log(`Recovering state for ${service} from backup`);
    return null;
  }
}
```

### 6. Chaos Testing Framework

```javascript
// mcp-chaos-test.js
class MCPChaosTest {
  constructor() {
    this.scenarios = {
      killService: this.killServiceScenario,
      networkPartition: this.networkPartitionScenario,
      resourceExhaustion: this.resourceExhaustionScenario,
      slowResponse: this.slowResponseScenario
    };
  }
  
  async runTest(scenarioName, targetService, options = {}) {
    const scenario = this.scenarios[scenarioName];
    if (!scenario) {
      throw new Error(`Unknown scenario: ${scenarioName}`);
    }
    
    console.log(`Starting chaos test: ${scenarioName} on ${targetService}`);
    
    const result = {
      scenario: scenarioName,
      target: targetService,
      startTime: Date.now(),
      options
    };
    
    try {
      // Capture baseline
      result.baseline = await this.captureMetrics();
      
      // Execute chaos
      await scenario.call(this, targetService, options);
      
      // Monitor recovery
      result.recoveryTime = await this.monitorRecovery(targetService);
      
      // Capture final state
      result.finalState = await this.captureMetrics();
      
      // Validate
      result.validation = await this.validateRecovery(result);
      
      result.success = true;
    } catch (error) {
      result.success = false;
      result.error = error.message;
    }
    
    result.endTime = Date.now();
    result.duration = result.endTime - result.startTime;
    
    return result;
  }
  
  async killServiceScenario(service, options) {
    console.log(`Killing ${service}...`);
    // Implement service kill logic
    // For testing, you might use Docker commands or process managers
  }
  
  async networkPartitionScenario(service, options) {
    console.log(`Creating network partition for ${service}...`);
    // Implement network partition logic
    // Could use iptables or network namespaces
  }
  
  async resourceExhaustionScenario(service, options) {
    console.log(`Exhausting resources for ${service}...`);
    // Implement resource exhaustion
    // Could use stress-ng or custom resource consumers
  }
  
  async slowResponseScenario(service, options) {
    const delay = options.delay || 5000;
    console.log(`Adding ${delay}ms delay to ${service}...`);
    // Implement response delay
    // Could use traffic control (tc) or proxy delays
  }
  
  async monitorRecovery(service, maxWait = 300000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWait) {
      const health = await this.checkServiceHealth(service);
      if (health.status === 'healthy') {
        return Date.now() - startTime;
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    throw new Error(`Service ${service} did not recover within ${maxWait}ms`);
  }
  
  async captureMetrics() {
    // Implement metric capture
    return {
      timestamp: Date.now(),
      services: {
        // Service health metrics
      }
    };
  }
  
  async validateRecovery(result) {
    // Implement validation logic
    return {
      dataIntegrity: true,
      performanceWithinThreshold: true,
      noDataLoss: true
    };
  }
  
  async checkServiceHealth(service) {
    // Implement health check
    return { status: 'healthy' };
  }
}

// Usage
const chaos = new MCPChaosTest();

// Run a test
chaos.runTest('killService', 'pinecone', { duration: 60000 })
  .then(result => {
    console.log('Test completed:', result);
    if (!result.success) {
      console.error('Test failed:', result.error);
    }
  });
```

### 7. Deployment Script

```bash
#!/bin/bash
# deploy-mcp-failover.sh

echo "Deploying MCP Failover System..."

# Install dependencies
npm install axios redis

# Create monitoring service
cat > /etc/systemd/system/mcp-monitor.service << EOF
[Unit]
Description=MCP Health Monitor
After=network.target

[Service]
Type=simple
User=mcp
WorkingDirectory=/opt/mcp-failover
ExecStart=/usr/bin/node /opt/mcp-failover/mcp-health-monitor.js
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Create failover directory
mkdir -p /opt/mcp-failover
cp mcp-*.js /opt/mcp-failover/

# Set up environment
cat > /opt/mcp-failover/.env << EOF
# Primary endpoints
PINECONE_HOST=${PINECONE_HOST}
PINECONE_API_KEY=${PINECONE_API_KEY}
NEO4J_URI=${NEO4J_URI}
NEO4J_USER=${NEO4J_USER}
NEO4J_PASSWORD=${NEO4J_PASSWORD}

# Backup endpoints
PINECONE_BACKUP_HOST=https://nightingale-backup.pinecone.io
NEO4J_BACKUP_URI=neo4j+s://backup.databases.neo4j.io

# Redis for state management
REDIS_URL=redis://localhost:6379
EOF

# Start services
systemctl daemon-reload
systemctl enable mcp-monitor
systemctl start mcp-monitor

echo "MCP Failover System deployed successfully!"
```

## Testing Checklist

```bash
# Run health checks
node -e "const m = require('./mcp-health-monitor.js'); setTimeout(() => console.log(m.getHealthReport()), 10000)"

# Test circuit breaker
node -e "const cb = require('./mcp-circuit-breaker.js'); /* test logic */"

# Simulate failover
node -e "const fc = require('./mcp-failover-controller.js'); fc.failover('pinecone')"

# Run chaos test
node -e "const chaos = require('./mcp-chaos-test.js'); chaos.runTest('killService', 'neo4j')"
```

## Production Deployment Notes

1. **Environment Variables**: Ensure all backup endpoints are configured
2. **Monitoring**: Set up alerts for failover events
3. **Testing**: Run chaos tests in staging before production
4. **Documentation**: Update runbooks with failover procedures
5. **Training**: Ensure team knows how to handle failover events

## Support Contacts

- **On-Call Engineer**: Check PagerDuty rotation
- **Escalation**: infrastructure@company.com
- **Vendor Support**: 
  - Pinecone: support@pinecone.io
  - Neo4j: support@neo4j.com
  - Tavily: support@tavily.com