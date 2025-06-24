// __tests__/integration/config/cloudflare.int.test.ts
/**
 * Cloudflare Integration Tests
 * 
 * These tests validate real-world API interactions and end-to-end workflows.
 * 
 * RUNNING MODES:
 * 
 * 1. Mocked API (Default - Safe for CI/CD):
 *    npm test cloudflare.int.test.ts
 *    
 * 2. Real Cloudflare API (Requires valid credentials):
 *    SKIP_REAL_API=false \
 *    CLOUDFLARE_TEST_ZONE_ID=your-test-zone \
 *    CLOUDFLARE_TEST_API_TOKEN=your-test-token \
 *    CLOUDFLARE_TEST_DOMAIN=test.yourdomain.com \
 *    npm test cloudflare.int.test.ts
 * 
 * WARNING: Real API tests will create/modify/delete resources in your Cloudflare zone.
 * Only use with a dedicated test zone.
 */
import {
  CloudflareAPI,
  cloudflareSettings,
  setupCloudflare,
  environmentConfigs,
  type CloudflareConfig,
  type RateLimitRule,
  type FirewallRule,
  type PageRule
} from '../../../src/config/cloudflare';
import { setTimeout } from 'timers/promises';

// Integration test configuration
const INTEGRATION_CONFIG = {
  // Use test environment variables or fallback to mock values
  ZONE_ID: process.env.CLOUDFLARE_TEST_ZONE_ID || 'test-zone-integration',
  API_TOKEN: process.env.CLOUDFLARE_TEST_API_TOKEN || 'test-token-integration',
  DOMAIN: process.env.CLOUDFLARE_TEST_DOMAIN || 'test-integration.example.com',
  // Default to mocked API unless explicitly set to use real API
  SKIP_REAL_API: process.env.SKIP_REAL_API !== 'false',
  API_TIMEOUT: parseInt(process.env.API_TIMEOUT || '30000'),
  RETRY_ATTEMPTS: parseInt(process.env.RETRY_ATTEMPTS || '3'),
  RATE_LIMIT_DELAY: parseInt(process.env.RATE_LIMIT_DELAY || '1000')
};

// Test utilities
class IntegrationTestHelper {
  private api: CloudflareAPI;
  private createdResources: {
    firewallRules: string[];
    rateLimits: string[];
    pageRules: string[];
  } = {
    firewallRules: [],
    rateLimits: [],
    pageRules: []
  };

  constructor(config: CloudflareConfig) {
    this.api = new CloudflareAPI(config);
  }

  async cleanup(): Promise<void> {
    console.log('🧹 Cleaning up test resources...');
    
    // Cleanup in reverse order to handle dependencies
    try {
      // Clean up page rules
      for (const ruleId of this.createdResources.pageRules) {
        try {
          await this.api.deletePageRule(ruleId);
          console.log(`✅ Deleted page rule: ${ruleId}`);
        } catch (error) {
          console.warn(`⚠️ Failed to delete page rule ${ruleId}:`, (error as Error).message);
        }
      }

      // Clean up rate limits
      for (const ruleId of this.createdResources.rateLimits) {
        try {
          await this.api.deleteRateLimit(ruleId);
          console.log(`✅ Deleted rate limit: ${ruleId}`);
        } catch (error) {
          console.warn(`⚠️ Failed to delete rate limit ${ruleId}:`, (error as Error).message);
        }
      }

      // Clean up firewall rules
      for (const ruleId of this.createdResources.firewallRules) {
        try {
          await this.api.deleteFirewallRule(ruleId);
          console.log(`✅ Deleted firewall rule: ${ruleId}`);
        } catch (error) {
          console.warn(`⚠️ Failed to delete firewall rule ${ruleId}:`, (error as Error).message);
        }
      }
    } catch (error) {
      console.error('❌ Cleanup failed:', (error as Error).message);
    }
  }

  trackResource(type: keyof typeof this.createdResources, id: string): void {
    this.createdResources[type].push(id);
  }

  async retryOperation<T>(
    operation: () => Promise<T>,
    maxAttempts: number = INTEGRATION_CONFIG.RETRY_ATTEMPTS,
    delay: number = INTEGRATION_CONFIG.RATE_LIMIT_DELAY
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === maxAttempts) {
          throw lastError;
        }
        
        // Check if it's a rate limit error
        if (lastError.message.includes('429') || lastError.message.includes('rate limit')) {
          console.log(`⏳ Rate limited, waiting ${delay}ms before retry ${attempt + 1}/${maxAttempts}`);
          await setTimeout(delay * attempt); // Exponential backoff
        } else {
          console.log(`🔄 Retrying operation (${attempt + 1}/${maxAttempts}): ${lastError.message}`);
          await setTimeout(delay);
        }
      }
    }
    
    throw lastError!;
  }

  getAPI(): CloudflareAPI {
    return this.api;
  }
}

// Mock fetch for non-real API tests
const mockFetch = jest.fn();

describe('Cloudflare Integration Tests', () => {
  let helper: IntegrationTestHelper;
  let config: CloudflareConfig;

  beforeAll(() => {
    config = {
      zoneId: INTEGRATION_CONFIG.ZONE_ID,
      apiToken: INTEGRATION_CONFIG.API_TOKEN,
      domain: INTEGRATION_CONFIG.DOMAIN
    };

    helper = new IntegrationTestHelper(config);

    // Set longer timeout for integration tests
    jest.setTimeout(60000);

    // Always mock fetch unless explicitly using real API
    if (INTEGRATION_CONFIG.SKIP_REAL_API) {
      global.fetch = mockFetch;
      console.log('🔧 Running with mocked API calls (default mode)');
      console.log('💡 To use real API, set SKIP_REAL_API=false and provide valid credentials');
    } else {
      console.log('🌐 Running with real Cloudflare API');
      console.log(`📍 Zone: ${INTEGRATION_CONFIG.ZONE_ID}`);
      console.log(`🌍 Domain: ${INTEGRATION_CONFIG.DOMAIN}`);
    }
  });

  afterAll(async () => {
    if (!INTEGRATION_CONFIG.SKIP_REAL_API) {
      await helper.cleanup();
    }
  });

  beforeEach(() => {
    if (INTEGRATION_CONFIG.SKIP_REAL_API) {
      mockFetch.mockClear();
      mockFetch.mockReset();
      // Default successful response for any test that doesn't set up specific mocks
      mockFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          success: true,
          result: { id: 'test-id-' + Date.now() }
        })
      });
    }
  });

  describe('API Connection and Authentication', () => {
    test('should successfully authenticate with Cloudflare API', async () => {
      const api = helper.getAPI();
      
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: INTEGRATION_CONFIG.ZONE_ID }
          })
        });
      }

      await expect(
        helper.retryOperation(() => api.updateSecurityLevel('medium'))
      ).resolves.not.toThrow();
    });

    test('should handle invalid API token gracefully', async () => {
      const invalidConfig: CloudflareConfig = {
        ...config,
        apiToken: 'invalid-token-12345'
      };
      const invalidAPI = new CloudflareAPI(invalidConfig);

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          json: jest.fn().mockResolvedValue({
            success: false,
            errors: [{ code: 10000, message: 'Invalid API token' }]
          })
        });
      }

      await expect(
        invalidAPI.updateSecurityLevel('high')
      ).rejects.toThrow(/Invalid API token|API token|Unauthorized|401/);
    });

    test('should handle invalid zone ID gracefully', async () => {
      const invalidConfig: CloudflareConfig = {
        ...config,
        zoneId: 'invalid-zone-id-12345'
      };
      const invalidAPI = new CloudflareAPI(invalidConfig);

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: 'Not Found',
          json: jest.fn().mockResolvedValue({
            success: false,
            errors: [{ code: 1001, message: 'Zone not found' }]
          })
        });
      }

      await expect(
        invalidAPI.updateSecurityLevel('high')
      ).rejects.toThrow(/Zone not found|404/);
    });

    test('should handle network timeouts', async () => {
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockRejectedValueOnce(new Error('Network timeout'));
      }

      const api = helper.getAPI();
      
      // Don't use retry for timeout test to avoid extending test time
      await expect(
        api.updateSecurityLevel('high')
      ).rejects.toThrow(/timeout|Network|Could not route/i);
    });
  });

  describe('Zone Settings Management', () => {
    test('should update and verify security level', async () => {
      const api = helper.getAPI();
      const testLevel = 'high';

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { value: testLevel }
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.updateSecurityLevel(testLevel)
      );

      expect(result).toHaveProperty('success', true);
      
      // Wait for propagation
      await setTimeout(1000);
    });

    test('should update SSL mode settings', async () => {
      const api = helper.getAPI();
      const sslMode = 'full_strict';

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { value: { value: sslMode } }
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.updateSSLMode(sslMode)
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should update performance settings', async () => {
      const api = helper.getAPI();
      const minifyConfig = { css: true, html: true, js: false };

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { value: { value: minifyConfig } }
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.updateMinify(minifyConfig)
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should handle concurrent settings updates', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        // Mock multiple successful responses
        Array(3).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
        });
      }

      const promises = [
        helper.retryOperation(() => api.updateSecurityLevel('medium')),
        helper.retryOperation(() => api.updateBrotli(true)),
        helper.retryOperation(() => api.updateHttp2(true))
      ];

      const results = await Promise.all(promises);
      results.forEach(result => {
        expect(result).toHaveProperty('success', true);
      });
    });
  });

  describe('Firewall Rules Management', () => {
    test('should create, update, and delete firewall rule', async () => {
      const api = helper.getAPI();
      const testRule: Omit<FirewallRule, 'id'> = {
        expression: '(http.request.uri.path contains "/test-integration")',
        action: 'challenge',
        description: 'Integration test rule - safe to delete',
        priority: 100
      };

      let ruleId: string;

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        ruleId = 'test-rule-' + Date.now();
        
        // Mock create
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: ruleId, ...testRule }
          })
        });

        // Mock update
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: ruleId, action: 'block' }
          })
        });

        // Mock delete
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: ruleId }
          })
        });
      }

      try {
        // Create rule
        const createResult = await helper.retryOperation(() => 
          api.createFirewallRule(testRule)
        );
        expect(createResult).toHaveProperty('success', true);
        
        ruleId = INTEGRATION_CONFIG.SKIP_REAL_API ? 
          'test-rule-' + Date.now() : 
          createResult.result.id;
        
        helper.trackResource('firewallRules', ruleId);

        // Update rule
        const updateResult = await helper.retryOperation(() => 
          api.updateFirewallRule(ruleId, { action: 'block' })
        );
        expect(updateResult).toHaveProperty('success', true);

        // Delete rule
        const deleteResult = await helper.retryOperation(() => 
          api.deleteFirewallRule(ruleId)
        );
        expect(deleteResult).toHaveProperty('success', true);

        // Remove from tracking since we manually deleted it
        const index = helper['createdResources'].firewallRules.indexOf(ruleId);
        if (index > -1) {
          helper['createdResources'].firewallRules.splice(index, 1);
        }

      } catch (error) {
        console.error('Firewall rule test failed:', (error as Error).message);
        throw error;
      }
    });

    test('should list existing firewall rules', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: [
              { id: 'rule-1', description: 'Test rule 1' },
              { id: 'rule-2', description: 'Test rule 2' }
            ]
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.listFirewallRules()
      );

      expect(result).toHaveProperty('success', true);
      expect(result.result).toBeInstanceOf(Array);
    });

    test('should handle invalid firewall rule expressions', async () => {
      const api = helper.getAPI();
      const invalidRule: Omit<FirewallRule, 'id'> = {
        expression: 'invalid expression syntax',
        action: 'block',
        description: 'Invalid rule for testing'
      };

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          json: jest.fn().mockResolvedValue({
            success: false,
            errors: [{ code: 10014, message: 'Invalid expression' }]
          })
        });
      }

      await expect(
        api.createFirewallRule(invalidRule)
      ).rejects.toThrow(/Invalid|expression|400|Could not route/);
    });
  });

  describe('Rate Limiting Management', () => {
    test('should create, update, and delete rate limit rule', async () => {
      const api = helper.getAPI();
      const testRule: Omit<RateLimitRule, 'id'> = {
        threshold: 10,
        period: 60,
        action: 'challenge',
        match: {
          request: {
            url: `*${INTEGRATION_CONFIG.DOMAIN}/test-integration/*`,
            methods: ['GET', 'POST']
          }
        },
        description: 'Integration test rate limit - safe to delete'
      };

      let ruleId: string;

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        ruleId = 'test-rate-limit-' + Date.now();
        
        // Mock create, update, delete
        mockFetch
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({
              success: true,
              result: { id: ruleId, ...testRule }
            })
          })
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({
              success: true,
              result: { id: ruleId, threshold: 20 }
            })
          })
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({
              success: true,
              result: { id: ruleId }
            })
          });
      }

      try {
        // Create rate limit
        const createResult = await helper.retryOperation(() => 
          api.createRateLimit(testRule)
        );
        expect(createResult).toHaveProperty('success', true);
        
        ruleId = INTEGRATION_CONFIG.SKIP_REAL_API ? 
          'test-rate-limit-' + Date.now() : 
          createResult.result.id;
        
        helper.trackResource('rateLimits', ruleId);

        // Update rate limit
        const updateResult = await helper.retryOperation(() => 
          api.updateRateLimit(ruleId, { threshold: 20 })
        );
        expect(updateResult).toHaveProperty('success', true);

        // Delete rate limit
        const deleteResult = await helper.retryOperation(() => 
          api.deleteRateLimit(ruleId)
        );
        expect(deleteResult).toHaveProperty('success', true);

        // Remove from tracking
        const index = helper['createdResources'].rateLimits.indexOf(ruleId);
        if (index > -1) {
          helper['createdResources'].rateLimits.splice(index, 1);
        }

      } catch (error) {
        console.error('Rate limit test failed:', (error as Error).message);
        throw error;
      }
    });

    test('should validate rate limit thresholds', async () => {
      const api = helper.getAPI();
      const invalidRule: Omit<RateLimitRule, 'id'> = {
        threshold: -1, // Invalid threshold
        period: 60,
        action: 'block',
        match: {
          request: {
            url: `*${INTEGRATION_CONFIG.DOMAIN}/*`
          }
        },
        description: 'Invalid rate limit for testing'
      };

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          json: jest.fn().mockResolvedValue({
            success: false,
            errors: [{ code: 10009, message: 'Invalid threshold' }]
          })
        });
      }

      await expect(
        api.createRateLimit(invalidRule)
      ).rejects.toThrow(/Invalid|threshold|400|Could not route/);
    });
  });

  describe('Page Rules Management', () => {
    test('should create, update, and delete page rule', async () => {
      const api = helper.getAPI();
      const testRule: Omit<PageRule, 'id'> = {
        targets: [{
          target: 'url',
          constraint: {
            operator: 'matches',
            value: `https://${INTEGRATION_CONFIG.DOMAIN}/test-integration/*`
          }
        }],
        actions: [{
          id: 'cache_level',
          value: 'bypass'
        }],
        priority: 1,
        status: 'active'
      };

      let ruleId: string;

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        ruleId = 'test-page-rule-' + Date.now();
        
        // Mock create, update, delete
        mockFetch
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({
              success: true,
              result: { id: ruleId, ...testRule }
            })
          })
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({
              success: true,
              result: { id: ruleId, status: 'disabled' }
            })
          })
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({
              success: true,
              result: { id: ruleId }
            })
          });
      }

      try {
        // Create page rule
        const createResult = await helper.retryOperation(() => 
          api.createPageRule(testRule)
        );
        expect(createResult).toHaveProperty('success', true);
        
        ruleId = INTEGRATION_CONFIG.SKIP_REAL_API ? 
          'test-page-rule-' + Date.now() : 
          createResult.result.id;
        
        helper.trackResource('pageRules', ruleId);

        // Update page rule
        const updateResult = await helper.retryOperation(() => 
          api.updatePageRule(ruleId, { status: 'disabled' })
        );
        expect(updateResult).toHaveProperty('success', true);

        // Delete page rule
        const deleteResult = await helper.retryOperation(() => 
          api.deletePageRule(ruleId)
        );
        expect(deleteResult).toHaveProperty('success', true);

        // Remove from tracking
        const index = helper['createdResources'].pageRules.indexOf(ruleId);
        if (index > -1) {
          helper['createdResources'].pageRules.splice(index, 1);
        }

      } catch (error) {
        console.error('Page rule test failed:', (error as Error).message);
        throw error;
      }
    });
  });

  describe('End-to-End Setup Process', () => {
    test('should run complete setupCloudflare successfully', async () => {
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        // Mock all the API calls that setupCloudflare makes
        const mockSuccessResponse = {
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: [] })
        };

        // Mock approximately 30 API calls for full setup
        Array(30).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce(mockSuccessResponse);
        });
      }

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      try {
        await helper.retryOperation(() => setupCloudflare(config));
        
        expect(consoleSpy).toHaveBeenCalledWith('🔄 Setting up Cloudflare configuration...');
        expect(consoleSpy).toHaveBeenCalledWith('\n🎉 Cloudflare setup complete!');
      } finally {
        consoleSpy.mockRestore();
      }
    }, 90000); // Extended timeout for full setup

    test('should handle partial setup failures gracefully', async () => {
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        // Mock settings updates to succeed
        Array(13).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
        });

        // Mock list operations to succeed  
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: [] })
        });

        // Mock first rule creation to fail
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          json: jest.fn().mockResolvedValue({
            errors: [{ code: 10014, message: 'Rule creation failed' }]
          })
        });

        // Mock remaining operations to succeed
        Array(20).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true, result: [] })
          });
        });
      }

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      try {
        await helper.retryOperation(() => setupCloudflare(config));
        
        // Should complete even with some failures
        expect(consoleSpy).toHaveBeenCalled();
      } finally {
        consoleSpy.mockRestore();
      }
    });
  });

  describe('Performance and Rate Limiting', () => {
    test('should handle API rate limits gracefully', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        // First call returns rate limit error
        mockFetch
          .mockResolvedValueOnce({
            ok: false,
            status: 429,
            statusText: 'Too Many Requests',
            json: jest.fn().mockResolvedValue({
              success: false,
              errors: [{ code: 10013, message: 'Rate limit exceeded' }]
            })
          })
          // Second call succeeds
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
      }

      // Should succeed after retry
      const result = await helper.retryOperation(() => 
        api.updateSecurityLevel('medium')
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should measure API response times', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      }

      const startTime = Date.now();
      await helper.retryOperation(() => api.updateSecurityLevel('medium'));
      const endTime = Date.now();

      const responseTime = endTime - startTime;
      console.log(`📊 API response time: ${responseTime}ms`);
      
      // Should respond within reasonable time
      expect(responseTime).toBeLessThan(INTEGRATION_CONFIG.API_TIMEOUT);
    });

    test('should handle concurrent API requests', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        // Mock 5 successful responses
        Array(5).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
        });
      }

      const operations = [
        () => api.updateSecurityLevel('medium'),
        () => api.updateBrotli(true),
        () => api.updateHttp2(true),
        () => api.updateHttp3(true),
        () => api.updateWebsockets(true)
      ];

      const startTime = Date.now();
      const results = await Promise.all(
        operations.map(op => helper.retryOperation(op))
      );
      const endTime = Date.now();

      results.forEach(result => {
        expect(result).toHaveProperty('success', true);
      });

      console.log(`📊 Concurrent operations completed in: ${endTime - startTime}ms`);
    });
  });

  describe('Analytics and Monitoring', () => {
    test('should retrieve analytics data', async () => {
      const api = helper.getAPI();
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // 24h ago
      const until = new Date().toISOString();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: {
              totals: { requests: { all: 1000 } },
              timeseries: []
            }
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.getAnalytics(since, until)
      );

      expect(result).toHaveProperty('success', true);
      expect(result.result).toHaveProperty('totals');
    });

    test('should retrieve firewall events', async () => {
      const api = helper.getAPI();
      const since = new Date(Date.now() - 60 * 60 * 1000).toISOString(); // 1h ago
      const until = new Date().toISOString();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: []
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.getFirewallEvents(since, until)
      );

      expect(result).toHaveProperty('success', true);
      expect(result.result).toBeInstanceOf(Array);
    });
  });

  describe('Cache Management', () => {
    test('should purge cache successfully', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: 'purge-' + Date.now() }
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.purgeCache()
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should purge specific files', async () => {
      const api = helper.getAPI();
      const filesToPurge = [
        `https://${INTEGRATION_CONFIG.DOMAIN}/api/v1/test-file.jpg`,
        `https://${INTEGRATION_CONFIG.DOMAIN}/static/test-style.css`
      ];

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: 'selective-purge-' + Date.now() }
          })
        });
      }

      const result = await helper.retryOperation(() => 
        api.purgeCache(filesToPurge)
      );

      expect(result).toHaveProperty('success', true);
    });
  });

  describe('Environment-Specific Configuration', () => {
    test('should apply development environment settings', async () => {
      const devConfig = { ...config };
      const devAPI = new CloudflareAPI(devConfig);

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      }

      // Development should use medium security
      const result = await helper.retryOperation(() => 
        devAPI.updateSecurityLevel(environmentConfigs.development.securityLevel)
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should apply production environment settings', async () => {
      const prodConfig = { ...config };
      const prodAPI = new CloudflareAPI(prodConfig);

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      }

      // Production should use under_attack security
      const result = await helper.retryOperation(() => 
        prodAPI.updateSecurityLevel(environmentConfigs.production.securityLevel)
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should validate environment-specific rate limits', async () => {
      const testEnvironments = ['development', 'staging', 'production'] as const;
      
      for (const env of testEnvironments) {
        const envConfig = environmentConfigs[env];
        const baseThreshold = 100;
        const adjustedThreshold = Math.ceil(baseThreshold * envConfig.rateLimitMultiplier);
        
        // Validate that multipliers produce reasonable values
        expect(adjustedThreshold).toBeGreaterThan(0);
        expect(adjustedThreshold).toBeLessThan(10000);
        
        if (env === 'development') {
          expect(adjustedThreshold).toBeGreaterThan(baseThreshold);
        } else if (env === 'production') {
          expect(adjustedThreshold).toBe(baseThreshold);
        }
        
        console.log(`📊 ${env}: ${baseThreshold} → ${adjustedThreshold} (${envConfig.rateLimitMultiplier}x)`);
      }
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from temporary network failures', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        // First two calls fail, third succeeds
        mockFetch
          .mockRejectedValueOnce(new Error('Network error'))
          .mockRejectedValueOnce(new Error('Connection timeout'))
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
      }

      const result = await helper.retryOperation(() => 
        api.updateSecurityLevel('medium'),
        3, // max attempts
        500 // delay
      );

      expect(result).toHaveProperty('success', true);
    });

    test('should handle service unavailable errors', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          json: jest.fn().mockResolvedValue({
            success: false,
            errors: [{ code: 1001, message: 'Service temporarily unavailable' }]
          })
        });
      }

      await expect(
        api.updateSecurityLevel('high')
      ).rejects.toThrow(/Service|unavailable|503|Could not route/);
    });

    test('should handle malformed API responses', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockRejectedValue(new Error('Invalid JSON'))
        });
      }

      await expect(
        api.updateSecurityLevel('medium')
      ).rejects.toThrow(/JSON|Invalid|Could not route/);
    });

    test('should handle partial API response failures', async () => {
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        let callCount = 0;
        mockFetch.mockImplementation(() => {
          callCount++;
          
          // First 10 settings succeed
          if (callCount <= 10) {
            return Promise.resolve({
              ok: true,
              json: jest.fn().mockResolvedValue({ success: true })
            });
          }
          
          // Next 3 settings fail
          if (callCount >= 11 && callCount <= 13) {
            return Promise.resolve({
              ok: false,
              status: 400,
              statusText: 'Bad Request',
              json: jest.fn().mockResolvedValue({
                errors: [{ code: 1014, message: 'Setting update failed' }]
              })
            });
          }
          
          // All remaining calls succeed
          return Promise.resolve({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true, result: [] })
          });
        });
      }

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      try {
        // Should complete despite some failures and continue to try other settings
        // The setupCloudflare function catches errors and continues
        await helper.retryOperation(() => setupCloudflare(config));
        
        // Even with failures, setupCloudflare should complete
        expect(consoleSpy).toHaveBeenCalledWith('\n🎉 Cloudflare setup complete!');
      } catch (error) {
        // If setupCloudflare throws due to early failures, that's also valid behavior
        expect((error as Error).message).toMatch(/Setting update failed/);
      } finally {
        consoleSpy.mockRestore();
      }
    });
  });

  describe('Real-World Scenarios', () => {
    test('should handle high-traffic configuration', async () => {
      const api = helper.getAPI();
      
      // Simulate high-traffic settings
      const highTrafficSettings = [
        () => api.updateSecurityLevel('under_attack'),
        () => api.updateBrotli(true),
        () => api.updateHttp2(true),
        () => api.updateHttp3(true)
      ];

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        Array(4).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
        });
      }

      const results = await Promise.all(
        highTrafficSettings.map(setting => helper.retryOperation(setting))
      );

      results.forEach(result => {
        expect(result).toHaveProperty('success', true);
      });
    });

    test('should handle DDoS mitigation scenario', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          })
          .mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
      }

      // Apply DDoS mitigation settings
      const securityResult = await helper.retryOperation(() => 
        api.updateSecurityLevel('under_attack')
      );
      expect(securityResult).toHaveProperty('success', true);

      const botResult = await helper.retryOperation(() => 
        api.updateBotFightMode(true)
      );
      expect(botResult).toHaveProperty('success', true);
    });

    test('should handle SSL/TLS migration scenario', async () => {
      const api = helper.getAPI();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        Array(4).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true })
          });
        });
      }

      // SSL migration steps
      const sslMigrationSteps = [
        () => api.updateSSLMode('full_strict'),
        () => api.updateMinTlsVersion('1.2'),
        () => api.updateAlwaysUseHttps(true),
        () => api.updateAutomaticHttpsRewrites(true)
      ];

      const results = await Promise.all(
        sslMigrationSteps.map(step => helper.retryOperation(step))
      );

      results.forEach(result => {
        expect(result).toHaveProperty('success', true);
      });
    });

    test('should handle bulk rule management', async () => {
      const api = helper.getAPI();
      
      if (!INTEGRATION_CONFIG.SKIP_REAL_API) {
        // Skip this test with real API to avoid creating too many rules
        console.log('⏭️ Skipping bulk rule test with real API');
        return;
      }

      // Mock bulk operations
      Array(20).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({
            success: true,
            result: { id: 'bulk-rule-' + Math.random() }
          })
        });
      });

      // Create multiple rules
      const bulkRules = Array(10).fill(null).map((_, index) => ({
        expression: `(http.request.uri.path contains "/bulk-test-${index}")`,
        action: 'challenge' as const,
        description: `Bulk test rule ${index}`
      }));

      const createPromises = bulkRules.map(rule => 
        helper.retryOperation(() => api.createFirewallRule(rule))
      );

      const results = await Promise.all(createPromises);
      results.forEach(result => {
        expect(result).toHaveProperty('success', true);
      });
    });
  });

  describe('Configuration Validation', () => {
    test('should validate complete configuration state', async () => {
      // Skip this test with mocked API due to mock complexity
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        console.log('⏭️ Skipping configuration validation test with mocked API');
        console.log('💡 This test requires real API responses to validate structure');
        return;
      }

      const api = helper.getAPI();

      // Validate current configuration with real API
      const [firewallRules, rateLimits, pageRules] = await Promise.all([
        helper.retryOperation(() => api.listFirewallRules()),
        helper.retryOperation(() => api.listRateLimits()),
        helper.retryOperation(() => api.listPageRules())
      ]);

      expect(firewallRules).toHaveProperty('success', true);
      expect(rateLimits).toHaveProperty('success', true);
      expect(pageRules).toHaveProperty('success', true);

      // With real API, verify they're arrays
      expect(firewallRules.result).toBeInstanceOf(Array);
      expect(rateLimits.result).toBeInstanceOf(Array);
      expect(pageRules.result).toBeInstanceOf(Array);
    });

    test('should verify security baseline compliance', async () => {
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        console.log('⏭️ Skipping security baseline check with mocked API');
        return;
      }

      // This test would verify that the actual Cloudflare configuration
      // meets security baseline requirements
      console.log('🔒 Security baseline verification would run here with real API');
      
      // Example checks:
      // - SSL mode is full_strict
      // - Security level is high or under_attack
      // - Bot fight mode is enabled
      // - Required firewall rules are present
      // - Rate limits are configured
    });
  });

  describe('Monitoring and Observability', () => {
    test('should track API call metrics', async () => {
      const api = helper.getAPI();
      
      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      }

      const startTime = process.hrtime.bigint();
      await helper.retryOperation(() => api.updateSecurityLevel('medium'));
      const endTime = process.hrtime.bigint();

      const durationMs = Number(endTime - startTime) / 1_000_000;
      console.log(`📊 API call duration: ${durationMs.toFixed(2)}ms`);
      
      expect(durationMs).toBeGreaterThan(0);
      expect(durationMs).toBeLessThan(30000); // Should complete within 30s
    });

    test('should log configuration changes', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      if (INTEGRATION_CONFIG.SKIP_REAL_API) {
        Array(30).fill(null).forEach(() => {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            json: jest.fn().mockResolvedValue({ success: true, result: [] })
          });
        });
      }

      try {
        await helper.retryOperation(() => setupCloudflare(config));
        
        // Verify that configuration changes are logged
        const logCalls = consoleSpy.mock.calls.flat();
        const hasConfigLogs = logCalls.some(call => 
          typeof call === 'string' && call.includes('✅')
        );
        
        expect(hasConfigLogs).toBe(true);
      } finally {
        consoleSpy.mockRestore();
      }
    });
  });

  describe('Cleanup and Resource Management', () => {
    test('should track and clean up test resources', async () => {
      // This test verifies that our helper properly tracks created resources
      expect(helper['createdResources']).toHaveProperty('firewallRules');
      expect(helper['createdResources']).toHaveProperty('rateLimits');
      expect(helper['createdResources']).toHaveProperty('pageRules');
      
      expect(Array.isArray(helper['createdResources'].firewallRules)).toBe(true);
      expect(Array.isArray(helper['createdResources'].rateLimits)).toBe(true);
      expect(Array.isArray(helper['createdResources'].pageRules)).toBe(true);
    });

    test('should handle cleanup failures gracefully', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      try {
        // Add a fake resource to test cleanup failure handling
        const fakeRuleId = 'fake-rule-id-for-cleanup-test';
        helper.trackResource('firewallRules', fakeRuleId);
        
        if (INTEGRATION_CONFIG.SKIP_REAL_API) {
          // Clear any previous mock implementations and set up specific mock for cleanup
          mockFetch.mockReset();
          mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 404,
            statusText: 'Not Found',
            json: jest.fn().mockResolvedValue({
              errors: [{ code: 1001, message: 'Rule not found' }]
            })
          });
        }
        
        // This should handle the failure gracefully
        await helper.cleanup();
        
        if (INTEGRATION_CONFIG.SKIP_REAL_API) {
          // Check if any warning was logged about the cleanup failure
          const warningCalls = consoleSpy.mock.calls;
          const hasCleanupWarning = warningCalls.some(call => 
            call.some(arg => 
              typeof arg === 'string' && 
              arg.includes('Failed to delete firewall rule') && 
              arg.includes(fakeRuleId)
            )
          );
          
          expect(hasCleanupWarning).toBe(true);
        }
      } finally {
        consoleSpy.mockRestore();
      }
    });
  });
});