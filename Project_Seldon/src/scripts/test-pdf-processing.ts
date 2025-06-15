#!/usr/bin/env node
/**
 * Test PDF Processing - Minimal Test Script
 * Tests PDF processing through ETL pipeline
 */

import { PDFProcessor } from '../processors/PDFProcessor';
import { logger } from '../utils/logger';
import path from 'path';
import fs from 'fs/promises';

async function testPDFProcessing() {
  logger.info('Starting PDF processing test');

  try {
    // Find a test PDF
    const testPdfPath = path.join(
      process.cwd(),
      '../../Current_advisories_2025_7_1/CISA Adds Five Known Exploited Vulnerabillities-2025_7_1.pdf'
    );

    // Check if file exists
    try {
      await fs.access(testPdfPath);
      logger.info(`Found test PDF: ${testPdfPath}`);
    } catch (error) {
      logger.error(`Test PDF not found at: ${testPdfPath}`);
      return;
    }

    // Initialize PDF processor
    const pdfProcessor = new PDFProcessor({
      chunkSize: 1000,
      chunkOverlap: 100,
      enableCitations: true,
      extractMetadata: true,
      cleanText: true
    });

    // Process the PDF
    logger.info('Processing PDF...');
    const result = await pdfProcessor.processPDF(testPdfPath);
    
    logger.info('PDF processed successfully!', {
      id: result.id,
      title: result.metadata.title,
      author: result.metadata.author,
      pages: result.metadata.pageCount,
      wordCount: result.content.wordCount,
      chunks: result.structure.sections.length
    });

    // Display first 500 characters of content
    logger.info('Content preview:', {
      preview: result.content.cleaned.substring(0, 500)
    });

    return result;

  } catch (error) {
    logger.error('PDF processing failed', error as Error);
    throw error;
  }
}

// Run the test
if (require.main === module) {
  testPDFProcessing()
    .then(() => {
      logger.info('Test completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Test failed', error);
      process.exit(1);
    });
}

export { testPDFProcessing };