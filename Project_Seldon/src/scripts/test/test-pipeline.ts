/**
 * Test Pipeline Runner for Project Seldon
 * Tests ETL pipeline with 5 sample reports from Annual_cyber_reports_2025
 */

import { logger } from './utils/logger';
import { ProjectSeldonETL } from './index';
import path from 'path';
import { readdir } from 'fs/promises';

// Test configuration
const TEST_CONFIG = {
  maxFiles: 5,
  reportDirectory: path.join(process.cwd(), '..', 'Annual_cyber_reports', 'Annual_cyber_reports_2023'),
  outputReport: true,
  validateResults: true,
};

interface TestResult {
  file: string;
  success: boolean;
  duration: number;
  error?: Error;
  stats?: any;
}

class ETLTestRunner {
  private etl: ProjectSeldonETL;
  private results: TestResult[] = [];

  constructor() {
    this.etl = new ProjectSeldonETL();
  }

  /**
   * Run the test pipeline
   */
  async run(): Promise<void> {
    logger.info('Starting Project Seldon ETL Test Pipeline', TEST_CONFIG);

    try {
      // Initialize ETL pipeline
      await this.etl.initialize();

      // Get test files
      const testFiles = await this.getTestFiles();
      logger.info(`Found ${testFiles.length} test files`);

      // Process each file
      for (const file of testFiles) {
        await this.processTestFile(file);
      }

      // Generate test report
      await this.generateTestReport();

      // Validate results
      if (TEST_CONFIG.validateResults) {
        await this.validateResults();
      }

      logger.info('Test pipeline completed successfully');
    } catch (error) {
      logger.error('Test pipeline failed', error as Error);
      throw error;
    } finally {
      await this.etl.cleanup();
    }
  }

  /**
   * Get test files from directory
   */
  private async getTestFiles(): Promise<string[]> {
    try {
      const files = await readdir(TEST_CONFIG.reportDirectory);
      const mdFiles = files
        .filter(f => f.endsWith('.md'))
        .slice(0, TEST_CONFIG.maxFiles)
        .map(f => path.join(TEST_CONFIG.reportDirectory, f));

      return mdFiles;
    } catch (error) {
      logger.error('Failed to read test directory', error as Error);
      throw error;
    }
  }

  /**
   * Process a single test file
   */
  private async processTestFile(filePath: string): Promise<void> {
    const fileName = path.basename(filePath);
    const startTime = Date.now();

    logger.info(`Processing test file: ${fileName}`);

    try {
      // Process the file using the main ETL pipeline
      await this.etl.processDirectory(path.dirname(filePath));

      const duration = Date.now() - startTime;
      
      this.results.push({
        file: fileName,
        success: true,
        duration,
        stats: {
          // Add specific stats here
        },
      });

      logger.info(`Successfully processed ${fileName} in ${duration}ms`);
    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.results.push({
        file: fileName,
        success: false,
        duration,
        error: error as Error,
      });

      logger.error(`Failed to process ${fileName}`, error as Error);
    }
  }

  /**
   * Generate test report
   */
  private async generateTestReport(): Promise<void> {
    if (!TEST_CONFIG.outputReport) return;

    const successCount = this.results.filter(r => r.success).length;
    const failureCount = this.results.filter(r => !r.success).length;
    const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);
    const averageDuration = totalDuration / this.results.length;

    const report = {
      summary: {
        totalFiles: this.results.length,
        successful: successCount,
        failed: failureCount,
        successRate: (successCount / this.results.length) * 100,
        totalDuration,
        averageDuration,
      },
      results: this.results.map(r => ({
        file: r.file,
        success: r.success,
        duration: r.duration,
        error: r.error?.message,
      })),
      timestamp: new Date().toISOString(),
    };

    logger.info('Test Report', report);

    // Write report to file
    const reportPath = path.join(process.cwd(), 'test-report.json');
    await require('fs/promises').writeFile(
      reportPath,
      JSON.stringify(report, null, 2)
    );

    logger.info(`Test report written to ${reportPath}`);
  }

  /**
   * Validate test results
   */
  private async validateResults(): Promise<void> {
    logger.info('Validating test results');

    const validations = {
      allFilesProcessed: this.results.length === TEST_CONFIG.maxFiles,
      successRate: this.results.filter(r => r.success).length / this.results.length >= 0.8,
      performanceCheck: this.results.every(r => r.duration < 60000), // 1 minute per file
    };

    const failed = Object.entries(validations)
      .filter(([_, passed]) => !passed)
      .map(([check]) => check);

    if (failed.length > 0) {
      throw new Error(`Validation failed: ${failed.join(', ')}`);
    }

    logger.info('All validations passed');
  }
}

// Performance monitoring
function monitorPerformance() {
  const usage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();

  logger.debug('Performance metrics', {
    memory: {
      rss: `${(usage.rss / 1024 / 1024).toFixed(2)} MB`,
      heapTotal: `${(usage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
      heapUsed: `${(usage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      external: `${(usage.external / 1024 / 1024).toFixed(2)} MB`,
    },
    cpu: {
      user: `${(cpuUsage.user / 1000000).toFixed(2)}s`,
      system: `${(cpuUsage.system / 1000000).toFixed(2)}s`,
    },
  });
}

// Main execution
async function main() {
  logger.info('='.repeat(80));
  logger.info('Project Seldon ETL Pipeline Test Runner');
  logger.info('Testing with Annual Cyber Reports 2023');
  logger.info('='.repeat(80));

  // Monitor performance every 10 seconds
  const perfInterval = setInterval(monitorPerformance, 10000);

  const runner = new ETLTestRunner();

  try {
    await runner.run();
    logger.info('✅ All tests completed successfully');
  } catch (error) {
    logger.error('❌ Test runner failed', error as Error);
    process.exit(1);
  } finally {
    clearInterval(perfInterval);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

export { ETLTestRunner };