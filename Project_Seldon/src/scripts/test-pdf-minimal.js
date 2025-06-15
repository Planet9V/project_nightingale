#!/usr/bin/env node
/**
 * Minimal PDF Test - JavaScript Only
 * Tests basic PDF parsing functionality
 */

const pdfParse = require('pdf-parse');
const fs = require('fs').promises;
const path = require('path');

async function testPDF() {
  console.log('Starting minimal PDF test...');
  
  const testPdfPath = '/home/jim/gtm-campaign-project/Current_advisories_2025_7_1/CISA Adds Five Known Exploited Vulnerabillities-2025_7_1.pdf';

  console.log('Looking for PDF at:', testPdfPath);

  try {
    // Check if file exists
    await fs.access(testPdfPath);
    console.log('PDF file found!');

    // Read PDF
    const dataBuffer = await fs.readFile(testPdfPath);
    console.log('PDF loaded, size:', dataBuffer.length, 'bytes');

    // Parse PDF
    console.log('Parsing PDF...');
    const pdfData = await pdfParse(dataBuffer);
    
    console.log('\n=== PDF Metadata ===');
    console.log('Pages:', pdfData.numpages);
    console.log('PDF Version:', pdfData.version);
    console.log('Title:', pdfData.info?.Title || 'N/A');
    console.log('Author:', pdfData.info?.Author || 'N/A');
    console.log('Subject:', pdfData.info?.Subject || 'N/A');
    console.log('Producer:', pdfData.info?.Producer || 'N/A');
    
    console.log('\n=== Content Stats ===');
    console.log('Text length:', pdfData.text.length, 'characters');
    console.log('First 500 characters:');
    console.log(pdfData.text.substring(0, 500));
    
    console.log('\n✅ PDF processing successful!');
    
    return pdfData;
    
  } catch (error) {
    console.error('❌ Error processing PDF:', error.message);
    throw error;
  }
}

// Run the test
testPDF()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));