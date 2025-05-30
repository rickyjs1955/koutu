// tests/instagramIntegrationSetup.ts
// Adapted to work with your existing test infrastructure

import { TestDatabaseConnection } from '../utils/testDatabaseConnection';
import { testQuery } from '../utils/testSetup';
import path from 'path';
import fs from 'fs/promises';

/**
 * Instagram-specific test setup that extends your existing test infrastructure
 */
export class InstagramIntegrationSetup {
  private static instance: InstagramIntegrationSetup;
  private testDataDir: string;
  private cleanupFiles: string[] = [];
  private cleanupDbRecords: Array<{ table: string; id: string }> = [];

  constructor() {
    this.testDataDir = path.join(__dirname, '../data/instagram');
  }

  static getInstance(): InstagramIntegrationSetup {
    if (!InstagramIntegrationSetup.instance) {
      InstagramIntegrationSetup.instance = new InstagramIntegrationSetup();
    }
    return InstagramIntegrationSetup.instance;
  }

  /**
   * Setup Instagram-specific database tables
   * Extends your existing test database with Instagram-specific tables
   */
  async setupInstagramTables(): Promise<void> {
    console.log('🔧 Setting up Instagram-specific test tables...');
    
    try {
      // Create Instagram-specific tables that extend your existing schema
      await testQuery(`
        CREATE TABLE IF NOT EXISTS instagram_imports (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          instagram_url TEXT NOT NULL,
          original_image_id UUID REFERENCES original_images(id) ON DELETE SET NULL,
          status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed')),
          error_message TEXT,
          retry_count INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(user_id, instagram_url)
        )
      `);

      await testQuery(`
        CREATE TABLE IF NOT EXISTS failed_instagram_imports (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          instagram_url TEXT NOT NULL,
          error_message TEXT,
          error_code VARCHAR(100),
          retry_count INTEGER DEFAULT 0,
          next_retry_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(user_id, instagram_url)
        )
      `);

      await testQuery(`
        CREATE TABLE IF NOT EXISTS user_instagram_tokens (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          access_token TEXT,
          refresh_token TEXT,
          expires_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await testQuery(`
        CREATE TABLE IF NOT EXISTS instagram_rate_limits (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          hit_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          endpoint VARCHAR(100),
          ip_address INET
        )
      `);

      // Create indexes for better performance
      await testQuery(`
        CREATE INDEX IF NOT EXISTS idx_instagram_imports_user_url 
        ON instagram_imports(user_id, instagram_url);
      `);

      await testQuery(`
        CREATE INDEX IF NOT EXISTS idx_failed_imports_retry 
        ON failed_instagram_imports(next_retry_at) WHERE next_retry_at IS NOT NULL;
      `);

      await testQuery(`
        CREATE INDEX IF NOT EXISTS idx_rate_limits_user_time 
        ON instagram_rate_limits(user_id, hit_at DESC);
      `);

      console.log('✅ Instagram test tables created successfully');
    } catch (error) {
      console.error('❌ Failed to setup Instagram tables:', error);
      throw error;
    }
  }

  /**
   * Setup test file system for Instagram files
   */
  async setupInstagramFileSystem(): Promise<void> {
    try {
      // Create Instagram-specific directories
      await fs.mkdir(this.testDataDir, { recursive: true });
      await fs.mkdir(path.join(this.testDataDir, 'uploads'), { recursive: true });
      await fs.mkdir(path.join(this.testDataDir, 'processed'), { recursive: true });
      await fs.mkdir(path.join(this.testDataDir, 'temp'), { recursive: true });
      
      console.log('✅ Instagram test file system setup complete');
    } catch (error) {
      console.error('❌ Failed to setup Instagram file system:', error);
      throw error;
    }
  }

  /**
   * Create a test user specifically for Instagram tests
   */
  async createInstagramTestUser(userIdSuffix?: string): Promise<string> {
    const userId = `instagram-test-user-${userIdSuffix || Date.now()}`;
    const email = `${userId}@test.com`;
    
    try {
      await testQuery(
        'INSERT INTO users (id, email, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())',
        [userId, email]
      );
      
      this.cleanupDbRecords.push({ table: 'users', id: userId });
      return userId;
    } catch (error) {
      console.error('Failed to create Instagram test user:', error);
      throw error;
    }
  }

  /**
   * Mock Instagram API responses for testing
   */
  setupInstagramApiMocks(): void {
    // Setup global fetch mock for Instagram API
    global.fetch = jest.fn();
    global.AbortController = jest.fn(() => ({
      abort: jest.fn(),
      signal: { aborted: false }
    })) as any;
    global.setTimeout = jest.fn((callback, delay) => {
      if (typeof callback === 'function') callback();
      return 123;
    }) as any;
    global.clearTimeout = jest.fn();
  }

  /**
   * Create mock Instagram image buffer for testing
   */
  async createMockInstagramImage(width: number = 1080, height: number = 1080): Promise<Buffer> {
    // Create a minimal valid JPEG buffer for testing
    const jpegHeader = Buffer.from([
      0xFF, 0xD8, // SOI (Start of Image)
      0xFF, 0xE0, // APP0
      0x00, 0x10, // Length
      0x4A, 0x46, 0x49, 0x46, 0x00, // JFIF
      0x01, 0x01, // Version
      0x01, 0x00, 0x01, 0x00, 0x01, // Density
      0x00, 0x00 // Thumbnail
    ]);
    
    const jpegEnd = Buffer.from([0xFF, 0xD9]); // EOI (End of Image)
    
    // Add some padding to simulate a real image
    const padding = Buffer.alloc(Math.max(1024, width * height / 100), 0x00);
    
    return Buffer.concat([jpegHeader, padding, jpegEnd]);
  }

  /**
   * Track files for cleanup
   */
  trackFileForCleanup(filePath: string): void {
    this.cleanupFiles.push(filePath);
  }

  /**
   * Track database records for cleanup
   */
  trackDbRecordForCleanup(table: string, id: string): void {
    this.cleanupDbRecords.push({ table, id });
  }

  /**
   * Cleanup Instagram-specific test data
   */
  async cleanupInstagramTestData(): Promise<void> {
    console.log('🧹 Cleaning up Instagram test data...');
    
    // Cleanup files
    for (const filePath of this.cleanupFiles) {
      try {
        await fs.unlink(filePath);
      } catch (error) {
        console.warn(`Failed to cleanup file ${filePath}:`, error);
      }
    }
    this.cleanupFiles = [];

    // Cleanup database records in correct order (respect foreign keys)
    const tableOrder = [
      'instagram_rate_limits',
      'user_instagram_tokens', 
      'failed_instagram_imports',
      'instagram_imports',
      'garment_items',
      'original_images',
      'users'
    ];
    
    for (const table of tableOrder) {
      const recordsToCleanup = this.cleanupDbRecords.filter(r => r.table === table);
      if (recordsToCleanup.length > 0) {
        try {
          const ids = recordsToCleanup.map(r => `'${r.id}'`).join(',');
          await testQuery(`DELETE FROM ${table} WHERE id IN (${ids})`);
        } catch (error) {
          console.warn(`Failed to cleanup ${table} records:`, error);
        }
      }
    }
    this.cleanupDbRecords = [];
  }

  /**
   * Cleanup Instagram test tables (for complete teardown)
   */
  async cleanupInstagramTables(): Promise<void> {
    try {
      const tables = [
        'instagram_rate_limits',
        'user_instagram_tokens',
        'failed_instagram_imports', 
        'instagram_imports'
      ];

      for (const table of tables) {
        await testQuery(`DROP TABLE IF EXISTS ${table} CASCADE`);
      }
      
      console.log('✅ Instagram test tables cleaned up');
    } catch (error) {
      console.warn('⚠️ Warning: Could not cleanup all Instagram tables:', error);
    }
  }

  /**
   * Cleanup Instagram test files (for complete teardown)
   */
  async cleanupInstagramFileSystem(): Promise<void> {
    try {
      // Remove all test files recursively
      await fs.rm(this.testDataDir, { recursive: true, force: true });
      console.log('✅ Instagram test files cleaned up');
    } catch (error) {
      console.warn('⚠️ Warning: Could not cleanup all Instagram test files:', error);
    }
  }

  /**
   * Get test data directory
   */
  getTestDataDir(): string {
    return this.testDataDir;
  }

  /**
   * Reset all mocks to clean state
   */
  resetMocks(): void {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  }
}

/**
 * Setup function to be called before Instagram integration tests
 */
export async function setupInstagramIntegrationTests(): Promise<void> {
  console.log('🚀 Setting up Instagram integration test environment...');
  
  const setup = InstagramIntegrationSetup.getInstance();
  
  try {
    // Use your existing database connection
    const pool = TestDatabaseConnection.getPool();
    if (!pool) {
      throw new Error('Test database not initialized. Make sure your test setup runs first.');
    }
    
    // Setup Instagram-specific extensions
    await setup.setupInstagramTables();
    await setup.setupInstagramFileSystem();
    setup.setupInstagramApiMocks();
    
    console.log('✅ Instagram integration test environment ready');
  } catch (error) {
    console.error('❌ Failed to setup Instagram integration test environment:', error);
    throw error;
  }
}

/**
 * Teardown function to be called after Instagram integration tests
 */
export async function teardownInstagramIntegrationTests(): Promise<void> {
  console.log('🧹 Tearing down Instagram integration test environment...');
  
  const setup = InstagramIntegrationSetup.getInstance();
  
  try {
    await setup.cleanupInstagramTestData();
    await setup.cleanupInstagramFileSystem();
    // Note: We don't drop tables here since they might be reused
    // Use cleanupInstagramTables() only for complete teardown
    
    setup.resetMocks();
    
    console.log('✅ Instagram integration test environment cleaned up');
  } catch (error) {
    console.error('❌ Failed to cleanup Instagram integration test environment:', error);
  }
}

/**
 * BeforeEach helper for Instagram integration tests
 */
export async function beforeEachInstagramTest(): Promise<InstagramIntegrationSetup> {
  const setup = InstagramIntegrationSetup.getInstance();
  await setup.cleanupInstagramTestData(); // Clean previous test data
  setup.resetMocks();
  return setup;
}

/**
 * AfterEach helper for Instagram integration tests
 */
export async function afterEachInstagramTest(): Promise<void> {
  const setup = InstagramIntegrationSetup.getInstance();
  await setup.cleanupInstagramTestData();
}

export default InstagramIntegrationSetup;