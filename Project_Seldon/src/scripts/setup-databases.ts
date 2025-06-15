#!/usr/bin/env node

const { createClient } = require('@supabase/supabase-js');
const { Pinecone } = require('@pinecone-database/pinecone');
const neo4j = require('neo4j-driver');
const fs = require('fs').promises;
const path = require('path');
const dotenv = require('dotenv');
const chalk = require('chalk');

// Load environment variables
dotenv.config();


interface SetupResult {
  service: string;
  success: boolean;
  message: string;
  error?: any;
}

class DatabaseSetup {
  private results: SetupResult[] = [];

  async setupAll(): Promise<void> {
    console.log(chalk.cyan('\n🚀 Setting up Project Seldon Databases\n'));
    
    // Run all setups
    await this.setupSupabase();
    await this.setupPinecone();
    await this.setupNeo4j();
    
    // Display results
    this.displayResults();
  }

  async setupSupabase(): Promise<void> {
    console.log(chalk.yellow('Setting up Supabase...'));
    
    try {
      const supabaseUrl = process.env.SUPABASE_URL;
      const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;
      
      if (!supabaseUrl || !supabaseKey) {
        throw new Error('Missing Supabase credentials');
      }

      const supabase = createClient(supabaseUrl, supabaseKey);
      
      // Read and execute schema
      const schemaPath = path.join(__dirname, '..', 'database', 'supabase-schema.sql');
      const schema = await fs.readFile(schemaPath, 'utf-8');
      
      // Split schema into individual statements
      const statements = schema
        .split(';')
        .map(s => s.trim())
        .filter(s => s.length > 0 && !s.startsWith('--'));
      
      let executed = 0;
      let failed = 0;
      
      for (const statement of statements) {
        try {
          // Skip DROP statements for safety
          if (statement.toUpperCase().includes('DROP TABLE')) {
            console.log(chalk.gray('  Skipping DROP statement for safety'));
            continue;
          }
          
          const { error } = await supabase.rpc('exec_sql', {
            sql: statement + ';'
          }).single();
          
          if (error) {
            console.log(chalk.red(`  ❌ Failed: ${statement.substring(0, 50)}...`));
            console.log(chalk.red(`     Error: ${error.message}`));
            failed++;
          } else {
            executed++;
          }
        } catch (err) {
          // Try direct execution as alternative
          try {
            const { error } = await supabase.from('_sql').select().single();
            if (error && error.code === '42P01') {
              // Table doesn't exist, likely first run
              console.log(chalk.yellow('  Note: Direct SQL execution not available, ensure schema is applied manually'));
              break;
            }
          } catch (e) {
            // Expected if RPC doesn't exist
          }
          failed++;
        }
      }
      
      // Test connection by checking if tables exist
      const { data: tables, error: tableError } = await supabase
        .from('documents')
        .select('id')
        .limit(1);
      
      if (!tableError) {
        this.results.push({
          service: 'Supabase',
          success: true,
          message: `Schema applied successfully (${executed} statements executed)`,
        });
        console.log(chalk.green('✅ Supabase setup complete'));
      } else {
        throw new Error(`Tables not accessible: ${tableError.message}`);
      }
      
    } catch (error) {
      this.results.push({
        service: 'Supabase',
        success: false,
        message: 'Failed to setup Supabase',
        error: error.message,
      });
      console.log(chalk.red('❌ Supabase setup failed'));
    }
  }

  async setupPinecone(): Promise<void> {
    console.log(chalk.yellow('\nSetting up Pinecone...'));
    
    try {
      const apiKey = process.env.PINECONE_API_KEY;
      if (!apiKey) {
        throw new Error('Missing Pinecone API key');
      }

      const pinecone = new Pinecone({ apiKey });
      
      // Check if index exists
      const indexes = await pinecone.listIndexes();
      const indexExists = indexes.indexes?.some(idx => idx.name === 'nightingale');
      
      if (!indexExists) {
        console.log(chalk.cyan('  Creating nightingale index...'));
        
        await pinecone.createIndex({
          name: 'nightingale',
          dimension: 768,
          metric: 'cosine',
          spec: {
            serverless: {
              cloud: 'aws',
              region: 'us-east-1',
            },
          },
        });
        
        // Wait for index to be ready
        console.log(chalk.cyan('  Waiting for index to be ready...'));
        let ready = false;
        let attempts = 0;
        
        while (!ready && attempts < 30) {
          await new Promise(resolve => setTimeout(resolve, 2000));
          const indexList = await pinecone.listIndexes();
          const index = indexList.indexes?.find(idx => idx.name === 'nightingale');
          ready = index?.status?.ready || false;
          attempts++;
        }
        
        if (ready) {
          this.results.push({
            service: 'Pinecone',
            success: true,
            message: 'Index created successfully',
          });
          console.log(chalk.green('✅ Pinecone index created'));
        } else {
          throw new Error('Index creation timed out');
        }
      } else {
        // Verify index configuration
        const index = indexes.indexes?.find(idx => idx.name === 'nightingale');
        if (index?.dimension !== 768) {
          throw new Error(`Index dimension ${index?.dimension} doesn't match required 768`);
        }
        
        this.results.push({
          service: 'Pinecone',
          success: true,
          message: 'Index already exists with correct configuration',
        });
        console.log(chalk.green('✅ Pinecone index verified'));
      }
      
    } catch (error) {
      this.results.push({
        service: 'Pinecone',
        success: false,
        message: 'Failed to setup Pinecone',
        error: error.message,
      });
      console.log(chalk.red('❌ Pinecone setup failed'));
    }
  }

  async setupNeo4j(): Promise<void> {
    console.log(chalk.yellow('\nSetting up Neo4j...'));
    
    const driver = neo4j.driver(
      process.env.NEO4J_URI!,
      neo4j.auth.basic(process.env.NEO4J_USER!, process.env.NEO4J_PASSWORD!)
    );
    
    const session = driver.session();
    
    try {
      // Test connection
      await driver.verifyConnectivity();
      console.log(chalk.cyan('  Connected to Neo4j'));
      
      // Create constraints
      const constraints = [
        'CREATE CONSTRAINT doc_id IF NOT EXISTS ON (d:Document) ASSERT d.id IS UNIQUE',
        'CREATE CONSTRAINT entity_id IF NOT EXISTS ON (e:Entity) ASSERT e.id IS UNIQUE',
        'CREATE CONSTRAINT threat_id IF NOT EXISTS ON (t:Threat) ASSERT t.id IS UNIQUE',
        'CREATE CONSTRAINT vendor_id IF NOT EXISTS ON (v:Vendor) ASSERT v.id IS UNIQUE',
        'CREATE CONSTRAINT report_id IF NOT EXISTS ON (r:Report) ASSERT r.id IS UNIQUE',
      ];
      
      for (const constraint of constraints) {
        try {
          await session.run(constraint);
          console.log(chalk.gray(`  ✓ ${constraint.substring(0, 50)}...`));
        } catch (err) {
          if (!err.message.includes('already exists')) {
            throw err;
          }
        }
      }
      
      // Create indexes
      const indexes = [
        'CREATE INDEX doc_title IF NOT EXISTS FOR (d:Document) ON (d.title)',
        'CREATE INDEX entity_name IF NOT EXISTS FOR (e:Entity) ON (e.name)',
        'CREATE INDEX threat_type IF NOT EXISTS FOR (t:Threat) ON (t.type)',
        'CREATE INDEX vendor_name IF NOT EXISTS FOR (v:Vendor) ON (v.name)',
        'CREATE INDEX report_date IF NOT EXISTS FOR (r:Report) ON (r.date)',
      ];
      
      for (const index of indexes) {
        try {
          await session.run(index);
          console.log(chalk.gray(`  ✓ ${index.substring(0, 50)}...`));
        } catch (err) {
          if (!err.message.includes('already exists')) {
            throw err;
          }
        }
      }
      
      // Create sample nodes for testing
      await session.run(`
        MERGE (d:Document {id: 'test-doc-1', title: 'Test Document'})
        MERGE (e:Entity {id: 'test-entity-1', name: 'Test Entity', type: 'organization'})
        MERGE (t:Threat {id: 'test-threat-1', name: 'Test Threat', type: 'ransomware'})
        MERGE (d)-[:MENTIONS]->(e)
        MERGE (e)-[:VULNERABLE_TO]->(t)
      `);
      
      this.results.push({
        service: 'Neo4j',
        success: true,
        message: 'Schema and constraints created successfully',
      });
      console.log(chalk.green('✅ Neo4j setup complete'));
      
    } catch (error) {
      this.results.push({
        service: 'Neo4j',
        success: false,
        message: 'Failed to setup Neo4j',
        error: error.message,
      });
      console.log(chalk.red('❌ Neo4j setup failed'));
    } finally {
      await session.close();
      await driver.close();
    }
  }

  displayResults(): void {
    console.log(chalk.cyan('\n📊 Setup Results:\n'));
    
    const table = this.results.map(r => ({
      Service: r.service,
      Status: r.success ? chalk.green('✅ Success') : chalk.red('❌ Failed'),
      Message: r.message,
      Error: r.error || '-',
    }));
    
    console.table(table);
    
    const allSuccess = this.results.every(r => r.success);
    
    if (allSuccess) {
      console.log(chalk.green('\n🎉 All databases setup successfully!'));
      console.log(chalk.cyan('\nNext steps:'));
      console.log('1. Run health check: npm run health-check');
      console.log('2. Start ETL pipeline: npm run etl');
    } else {
      console.log(chalk.red('\n⚠️  Some databases failed to setup'));
      console.log(chalk.yellow('\nTroubleshooting:'));
      console.log('1. Check your .env file has all required credentials');
      console.log('2. Ensure all services are accessible');
      console.log('3. Check the error messages above');
    }
  }
}

// Run setup
async function main() {
  const setup = new DatabaseSetup();
  await setup.setupAll();
}

main().catch(console.error);