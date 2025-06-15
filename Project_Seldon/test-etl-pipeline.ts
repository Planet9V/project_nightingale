#!/usr/bin/env node

/**
 * Test ETL Pipeline for Project Seldon
 * 
 * This script demonstrates the ETL pipeline by processing a subset of 
 * Annual Cyber Reports from 2025 without moving or deleting any files.
 */

import { readFile, readdir, mkdir, writeFile } from 'fs/promises';
import { join, basename } from 'path';
import { createHash } from 'crypto';

// Configuration
const CONFIG = {
  sourceDir: '/home/jim/gtm-campaign-project/Annual_cyber_reports/Annual_cyber_reports_2025',
  stagingDir: '/home/jim/gtm-campaign-project/Project_Seldon/data/staging',
  outputDir: '/home/jim/gtm-campaign-project/Project_Seldon/data/output',
  testLimit: 5, // Process only 5 files for testing
  jinaApiKey: process.env.JINA_API_KEY || 'jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q'
};

// Simple document metadata extraction
interface DocumentMetadata {
  id: string;
  title: string;
  source: string;
  year: number;
  vendor: string;
  reportType: string;
  hash: string;
  fileSize: number;
  processedAt: string;
}

// Extract metadata from filename
function extractMetadataFromFilename(filename: string): Partial<DocumentMetadata> {
  // Remove .md extension
  const baseName = filename.replace('.md', '');
  
  // Extract vendor (first part before hyphen)
  const parts = baseName.split('-');
  const vendor = parts[0];
  
  // Extract report type and year
  const year = 2025;
  const reportType = parts.slice(1, -1).join(' ');
  
  return {
    vendor,
    year,
    reportType,
    title: baseName.replace(/-/g, ' ')
  };
}

// Process a single document
async function processDocument(filePath: string): Promise<DocumentMetadata> {
  const filename = basename(filePath);
  const content = await readFile(filePath, 'utf-8');
  const hash = createHash('sha256').update(content).digest('hex');
  
  // Extract metadata
  const metadata = extractMetadataFromFilename(filename);
  
  // Create document metadata
  const doc: DocumentMetadata = {
    id: hash.substring(0, 16),
    title: metadata.title || filename,
    source: filePath,
    year: metadata.year || 2025,
    vendor: metadata.vendor || 'Unknown',
    reportType: metadata.reportType || 'Security Report',
    hash,
    fileSize: content.length,
    processedAt: new Date().toISOString()
  };
  
  // Extract key sections
  const sections = extractSections(content);
  
  // Generate summary (simple version for now)
  const summary = generateSummary(content);
  
  // Save processed document
  const outputPath = join(CONFIG.outputDir, `${doc.id}_processed.json`);
  await writeFile(outputPath, JSON.stringify({
    metadata: doc,
    sections,
    summary,
    contentPreview: content.substring(0, 500) + '...'
  }, null, 2));
  
  return doc;
}

// Extract sections from markdown
function extractSections(content: string): Record<string, string> {
  const sections: Record<string, string> = {};
  const lines = content.split('\n');
  let currentSection = 'Introduction';
  let sectionContent: string[] = [];
  
  for (const line of lines) {
    if (line.startsWith('# ')) {
      if (sectionContent.length > 0) {
        sections[currentSection] = sectionContent.join('\n').trim();
      }
      currentSection = line.substring(2).trim();
      sectionContent = [];
    } else {
      sectionContent.push(line);
    }
  }
  
  // Don't forget the last section
  if (sectionContent.length > 0) {
    sections[currentSection] = sectionContent.join('\n').trim();
  }
  
  return sections;
}

// Generate a simple summary
function generateSummary(content: string): string {
  const lines = content.split('\n').filter(line => line.trim().length > 0);
  const firstParagraph = lines.find(line => !line.startsWith('#') && line.length > 50);
  return firstParagraph || lines[0] || 'No summary available';
}

// Main ETL pipeline
async function runETLPipeline() {
  console.log('🚀 Starting Project Seldon ETL Pipeline Test');
  console.log('=' .repeat(50));
  
  try {
    // Create directories
    await mkdir(CONFIG.stagingDir, { recursive: true });
    await mkdir(CONFIG.outputDir, { recursive: true });
    
    // List available files
    const files = await readdir(CONFIG.sourceDir);
    const mdFiles = files.filter(f => f.endsWith('.md')).slice(0, CONFIG.testLimit);
    
    console.log(`\n📁 Found ${files.length} files in source directory`);
    console.log(`📋 Processing ${mdFiles.length} files for test run\n`);
    
    // Process each file
    const results: DocumentMetadata[] = [];
    
    for (const file of mdFiles) {
      console.log(`\n📄 Processing: ${file}`);
      const filePath = join(CONFIG.sourceDir, file);
      
      try {
        const metadata = await processDocument(filePath);
        results.push(metadata);
        
        console.log(`  ✅ Vendor: ${metadata.vendor}`);
        console.log(`  ✅ Report Type: ${metadata.reportType}`);
        console.log(`  ✅ Document ID: ${metadata.id}`);
        console.log(`  ✅ File Size: ${(metadata.fileSize / 1024).toFixed(2)} KB`);
      } catch (error) {
        console.error(`  ❌ Error processing ${file}:`, error);
      }
    }
    
    // Generate manifest
    const manifest = {
      pipelineRun: {
        timestamp: new Date().toISOString(),
        filesProcessed: results.length,
        totalSize: results.reduce((sum, doc) => sum + doc.fileSize, 0),
        configuration: CONFIG
      },
      documents: results,
      statistics: {
        byVendor: groupBy(results, 'vendor'),
        byReportType: groupBy(results, 'reportType'),
        averageFileSize: results.reduce((sum, doc) => sum + doc.fileSize, 0) / results.length
      }
    };
    
    // Save manifest
    const manifestPath = join(CONFIG.outputDir, 'pipeline_manifest.json');
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    
    console.log('\n' + '=' .repeat(50));
    console.log('✅ ETL Pipeline Test Complete!');
    console.log(`📊 Processed ${results.length} documents`);
    console.log(`💾 Output saved to: ${CONFIG.outputDir}`);
    console.log(`📋 Manifest saved to: ${manifestPath}`);
    
    // Show sample results
    console.log('\n📈 Sample Results:');
    console.log('Vendors processed:', Object.keys(groupBy(results, 'vendor')).join(', '));
    console.log('Report types:', Object.keys(groupBy(results, 'reportType')).slice(0, 3).join(', '), '...');
    
  } catch (error) {
    console.error('\n❌ Pipeline Error:', error);
    process.exit(1);
  }
}

// Helper function to group by property
function groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
  return array.reduce((result, item) => {
    const group = String(item[key]);
    if (!result[group]) result[group] = [];
    result[group].push(item);
    return result;
  }, {} as Record<string, T[]>);
}

// Run the pipeline
if (import.meta.url === `file://${process.argv[1]}`) {
  runETLPipeline().catch(console.error);
}

export { runETLPipeline, processDocument };