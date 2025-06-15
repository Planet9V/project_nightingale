#!/usr/bin/env node

const { createClient } = require('@supabase/supabase-js');
const { Pinecone } = require('@pinecone-database/pinecone');
const neo4j = require('neo4j-driver');
const axios = require('axios');
const dotenv = require('dotenv');
const chalk = require('chalk');

// Load environment variables
dotenv.config();

async function testSupabase() {
  console.log(chalk.yellow('\n🔍 Testing Supabase connection...'));
  
  try {
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );
    
    // Simple test query
    const { data, error } = await supabase
      .from('documents')
      .select('count', { count: 'exact', head: true });
    
    if (error) {
      if (error.code === '42P01') {
        console.log(chalk.red('❌ Tables not created yet'));
        console.log(chalk.yellow('   Run the SQL schema manually in Supabase dashboard'));
      } else {
        throw error;
      }
    } else {
      console.log(chalk.green('✅ Supabase connected successfully'));
      console.log(chalk.gray(`   Document count: ${data || 0}`));
    }
  } catch (error) {
    console.log(chalk.red('❌ Supabase connection failed'));
    console.log(chalk.gray(`   Error: ${error.message}`));
  }
}

async function testPinecone() {
  console.log(chalk.yellow('\n🔍 Testing Pinecone connection...'));
  
  try {
    const pinecone = new Pinecone({
      apiKey: process.env.PINECONE_API_KEY
    });
    
    const indexes = await pinecone.listIndexes();
    console.log(chalk.green('✅ Pinecone connected successfully'));
    console.log(chalk.gray(`   Indexes: ${indexes.indexes?.map(i => i.name).join(', ') || 'none'}`));
    
    const nightingale = indexes.indexes?.find(i => i.name === 'nightingale');
    if (nightingale) {
      console.log(chalk.gray(`   Nightingale index: ${nightingale.dimension}d ${nightingale.metric}`));
    }
  } catch (error) {
    console.log(chalk.red('❌ Pinecone connection failed'));
    console.log(chalk.gray(`   Error: ${error.message}`));
  }
}

async function testNeo4j() {
  console.log(chalk.yellow('\n🔍 Testing Neo4j connection...'));
  
  const driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD)
  );
  
  try {
    await driver.verifyConnectivity();
    console.log(chalk.green('✅ Neo4j connected successfully'));
    
    const session = driver.session();
    try {
      const result = await session.run('MATCH (n) RETURN count(n) as count');
      const count = result.records[0].get('count').toNumber();
      console.log(chalk.gray(`   Node count: ${count}`));
    } finally {
      await session.close();
    }
  } catch (error) {
    console.log(chalk.red('❌ Neo4j connection failed'));
    console.log(chalk.gray(`   Error: ${error.message}`));
  } finally {
    await driver.close();
  }
}

async function testJina() {
  console.log(chalk.yellow('\n🔍 Testing Jina AI connection...'));
  
  try {
    const response = await axios.post(
      'https://api.jina.ai/v1/embeddings',
      {
        input: ['test'],
        model: 'jina-embeddings-v2-base-en'
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.JINA_API_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      }
    );
    
    if (response.data?.data?.[0]?.embedding) {
      const dim = response.data.data[0].embedding.length;
      console.log(chalk.green('✅ Jina AI connected successfully'));
      console.log(chalk.gray(`   Embedding dimension: ${dim}`));
    }
  } catch (error) {
    console.log(chalk.red('❌ Jina AI connection failed'));
    console.log(chalk.gray(`   Error: ${error.response?.data?.error || error.message}`));
  }
}

async function main() {
  console.log(chalk.cyan('🧪 Testing Project Seldon Connections'));
  console.log(chalk.gray('=' .repeat(50)));
  
  await testSupabase();
  await testPinecone();
  await testNeo4j();
  await testJina();
  
  console.log(chalk.cyan('\n' + '=' .repeat(50)));
  console.log(chalk.cyan('Test complete!'));
}

main().catch(console.error);