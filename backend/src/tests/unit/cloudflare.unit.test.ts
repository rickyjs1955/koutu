// __tests__/unit/config/cloudflare.unit.test.ts
import {
  CloudflareAPI,
  cloudflareSettings,
  setupCloudflare,
  environmentConfigs,
  type CloudflareConfig,
  type RateLimitRule,
  type FirewallRule,
  type PageRule,
  type SecurityLevel,
  type SslMode,
  type MinifySetting
} from '../../config/cloudflare';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('Cloudflare Configuration Unit Tests', () => {
  // Reset mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockClear();
  });

  // Helper function to create successful setup mocks
  const createSuccessfulSetupMocks = () => {
    // Settings updates (13 calls)
    const settingsMocks = Array(13).fill({
      ok: true,
      json: jest.fn().mockResolvedValue({ success: true })
    });

    // Based on cloudflareSettings:
    // - 5 WAF rules + 1 list call = 6 calls
    // - 4 rate limit rules + 1 list call = 5 calls  
    // - 3 page rules + 1 list call = 4 calls
    // Total: 13 + 15 = 28 calls minimum
    const operationMocks = Array(20).fill({
      ok: true,
      json: jest.fn().mockResolvedValue({ success: true, result: [] })
    });

    [...settingsMocks, ...operationMocks].forEach(mock => {
      mockFetch.mockResolvedValueOnce(mock);
    });
  };

  describe('Type Definitions and Interfaces', () => {
    test('should have correct CloudflareConfig interface structure', () => {
      const config: CloudflareConfig = {
        zoneId: 'test-zone-id',
        apiToken: 'test-token',
        domain: 'test-domain.com',
        subdomain: 'api'
      };

      expect(config.zoneId).toBe('test-zone-id');
      expect(config.apiToken).toBe('test-token');
      expect(config.domain).toBe('test-domain.com');
      expect(config.subdomain).toBe('api');
    });

    test('should have correct RateLimitRule interface structure', () => {
      const rule: RateLimitRule = {
        id: 'test-id',
        threshold: 100,
        period: 60,
        action: 'block',
        match: {
          request: {
            url: 'test.com/*',
            methods: ['GET', 'POST']
          }
        },
        description: 'Test rule'
      };

      expect(rule.threshold).toBe(100);
      expect(rule.period).toBe(60);
      expect(rule.action).toBe('block');
      expect(rule.match.request.url).toBe('test.com/*');
      expect(rule.description).toBe('Test rule');
    });

    test('should have correct FirewallRule interface structure', () => {
      const rule: FirewallRule = {
        id: 'test-firewall-id',
        expression: 'http.request.uri.path contains "/admin"',
        action: 'block',
        description: 'Block admin access',
        priority: 1,
        paused: false
      };

      expect(rule.expression).toBe('http.request.uri.path contains "/admin"');
      expect(rule.action).toBe('block');
      expect(rule.priority).toBe(1);
      expect(rule.paused).toBe(false);
    });

    test('should have correct PageRule interface structure', () => {
      const rule: PageRule = {
        id: 'test-page-rule-id',
        targets: [{
          target: 'url',
          constraint: {
            operator: 'matches',
            value: 'https://test.com/api/*'
          }
        }],
        actions: [{
          id: 'cache_level',
          value: 'cache_everything'
        }],
        priority: 1,
        status: 'active'
      };

      expect(rule.targets[0].target).toBe('url');
      expect(rule.targets[0].constraint.operator).toBe('matches');
      expect(rule.actions[0].id).toBe('cache_level');
      expect(rule.status).toBe('active');
    });
  });

  describe('CloudflareAPI Class', () => {
    let api: CloudflareAPI;
    const mockConfig: CloudflareConfig = {
      zoneId: 'test-zone-123',
      apiToken: 'test-token-456',
      domain: 'example.com'
    };

    beforeEach(() => {
      api = new CloudflareAPI(mockConfig);
      // Reset mocks for each test in this describe block
      mockFetch.mockReset();
    });

    describe('Constructor', () => {
      test('should initialize with correct config', () => {
        expect(api).toBeInstanceOf(CloudflareAPI);
        // Access private config through type assertion for testing
        expect((api as any).config).toEqual(mockConfig);
        expect((api as any).baseUrl).toBe('https://api.cloudflare.com/client/v4');
      });
    });

    describe('makeRequest method', () => {
      test('should make successful API request', async () => {
        const mockResponse = { success: true, result: { id: 'test' } };
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValueOnce(mockResponse)
        });

        const result = await (api as any).makeRequest('GET', '/test-endpoint');

        expect(mockFetch).toHaveBeenCalledWith(
          'https://api.cloudflare.com/client/v4/test-endpoint',
          {
            method: 'GET',
            headers: {
              'Authorization': 'Bearer test-token-456',
              'Content-Type': 'application/json'
            },
            body: undefined
          }
        );
        expect(result).toEqual(mockResponse);
      });

      test('should handle API request with data', async () => {
        const mockResponse = { success: true, result: { id: 'test' } };
        const testData = { setting: 'value' };
        
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValueOnce(mockResponse)
        });

        await (api as any).makeRequest('POST', '/test-endpoint', testData);

        expect(mockFetch).toHaveBeenCalledWith(
          'https://api.cloudflare.com/client/v4/test-endpoint',
          {
            method: 'POST',
            headers: {
              'Authorization': 'Bearer test-token-456',
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(testData)
          }
        );
      });

      test('should handle API errors with error details', async () => {
        const mockErrorResponse = {
          errors: [
            { code: 1001, message: 'Test error message' },
            { code: 1002, message: 'Another error' }
          ]
        };
        
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          json: jest.fn().mockResolvedValueOnce(mockErrorResponse)
        });

        await expect((api as any).makeRequest('GET', '/test-endpoint'))
          .rejects.toThrow('Cloudflare API error (400 Bad Request): Code: 1001, Message: Test error message; Code: 1002, Message: Another error');
      });

      test('should handle API errors without error details', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          json: jest.fn().mockResolvedValueOnce({})
        });

        await expect((api as any).makeRequest('GET', '/test-endpoint'))
          .rejects.toThrow('Cloudflare API error (500 Internal Server Error): No specific error message from Cloudflare.');
      });

      test('should handle network errors', async () => {
        mockFetch.mockRejectedValueOnce(new Error('Network error'));

        await expect((api as any).makeRequest('GET', '/test-endpoint'))
          .rejects.toThrow('Network error');
      });
    });

    describe('Zone Settings Methods', () => {
      beforeEach(() => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });

      test('should update zone setting', async () => {
        await api.updateZoneSetting('test_setting', 'test_value');

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/settings/test_setting`,
          expect.objectContaining({
            method: 'PATCH',
            body: JSON.stringify({ value: 'test_value' })
          })
        );
      });

      test('should update security level', async () => {
        await api.updateSecurityLevel('high');

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/settings/security_level`,
          expect.objectContaining({
            method: 'PATCH',
            body: JSON.stringify({ value: 'high' })
          })
        );
      });

      test('should update SSL mode', async () => {
        await api.updateSSLMode('full_strict');

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/settings/ssl`,
          expect.objectContaining({
            method: 'PATCH',
            body: JSON.stringify({ value: { value: 'full_strict' } })
          })
        );
      });

      test('should update minify settings', async () => {
        const minifyConfig: MinifySetting = { css: true, html: false, js: true };
        await api.updateMinify(minifyConfig);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/settings/minify`,
          expect.objectContaining({
            method: 'PATCH',
            body: JSON.stringify({ value: { value: minifyConfig } })
          })
        );
      });

      test('should update boolean settings correctly', async () => {
        await api.updateBrotli(true);
        expect(mockFetch).toHaveBeenLastCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/settings/brotli`,
          expect.objectContaining({
            body: JSON.stringify({ value: 'on' })
          })
        );

        await api.updateBrotli(false);
        expect(mockFetch).toHaveBeenLastCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/settings/brotli`,
          expect.objectContaining({
            body: JSON.stringify({ value: 'off' })
          })
        );
      });

      test('should purge cache without files', async () => {
        await api.purgeCache();

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/purge_cache`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ purge_everything: true })
          })
        );
      });

      test('should purge specific files', async () => {
        const files = ['https://example.com/file1.jpg', 'https://example.com/file2.css'];
        await api.purgeCache(files);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/purge_cache`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ files })
          })
        );
      });
    });

    describe('Firewall Rules Methods', () => {
      beforeEach(() => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: [] })
        });
      });

      test('should create firewall rule', async () => {
        const rule: Omit<FirewallRule, 'id'> = {
          expression: 'http.request.uri.path contains "/admin"',
          action: 'block',
          description: 'Block admin access',
          priority: 1,
          paused: false
        };

        await api.createFirewallRule(rule);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/firewall/rules`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              action: rule.action,
              filter: {
                expression: rule.expression,
                description: rule.description,
                paused: rule.paused
              },
              description: rule.description,
              priority: rule.priority,
              paused: rule.paused
            })
          })
        );
      });

      test('should update firewall rule', async () => {
        const updates = { action: 'challenge' as const };
        await api.updateFirewallRule('rule-123', updates);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/firewall/rules/rule-123`,
          expect.objectContaining({
            method: 'PUT',
            body: JSON.stringify(updates)
          })
        );
      });

      test('should delete firewall rule', async () => {
        await api.deleteFirewallRule('rule-123');

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/firewall/rules/rule-123`,
          expect.objectContaining({ method: 'DELETE' })
        );
      });

      test('should list firewall rules', async () => {
        await api.listFirewallRules();

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/firewall/rules`,
          expect.objectContaining({ method: 'GET' })
        );
      });
    });

    describe('Rate Limiting Methods', () => {
      beforeEach(() => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: [] })
        });
      });

      test('should create rate limit rule', async () => {
        const rule: Omit<RateLimitRule, 'id'> = {
          threshold: 100,
          period: 60,
          action: 'block',
          match: {
            request: {
              url: 'example.com/api/*',
              methods: ['GET', 'POST']
            }
          },
          description: 'API rate limit'
        };

        await api.createRateLimit(rule);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/rate_limits`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              threshold: rule.threshold,
              period: rule.period,
              action: {
                mode: rule.action,
                timeout: 86400
              },
              match: rule.match,
              description: rule.description
            })
          })
        );
      });

      test('should create rate limit rule with non-block action', async () => {
        const rule: Omit<RateLimitRule, 'id'> = {
          threshold: 50,
          period: 60,
          action: 'challenge',
          match: {
            request: { url: 'example.com/*' }
          },
          description: 'Challenge rate limit'
        };

        await api.createRateLimit(rule);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/rate_limits`,
          expect.objectContaining({
            body: JSON.stringify({
              threshold: rule.threshold,
              period: rule.period,
              action: {
                mode: rule.action,
                timeout: undefined
              },
              match: rule.match,
              description: rule.description
            })
          })
        );
      });

      test('should update rate limit rule', async () => {
        const updates = { threshold: 200 };
        await api.updateRateLimit('limit-123', updates);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/rate_limits/limit-123`,
          expect.objectContaining({
            method: 'PUT',
            body: JSON.stringify(updates)
          })
        );
      });

      test('should delete rate limit rule', async () => {
        await api.deleteRateLimit('limit-123');

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/rate_limits/limit-123`,
          expect.objectContaining({ method: 'DELETE' })
        );
      });

      test('should list rate limits', async () => {
        await api.listRateLimits();

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/rate_limits`,
          expect.objectContaining({ method: 'GET' })
        );
      });
    });

    describe('Page Rules Methods', () => {
      beforeEach(() => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: [] })
        });
      });

      test('should create page rule', async () => {
        const rule: Omit<PageRule, 'id'> = {
          targets: [{
            target: 'url',
            constraint: {
              operator: 'matches',
              value: 'https://example.com/api/*'
            }
          }],
          actions: [{
            id: 'cache_level',
            value: 'cache_everything'
          }],
          priority: 1,
          status: 'active'
        };

        await api.createPageRule(rule);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/pagerules`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify(rule)
          })
        );
      });

      test('should update page rule', async () => {
        const updates = { status: 'disabled' as const };
        await api.updatePageRule('page-123', updates);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/pagerules/page-123`,
          expect.objectContaining({
            method: 'PATCH',
            body: JSON.stringify(updates)
          })
        );
      });

      test('should delete page rule', async () => {
        await api.deletePageRule('page-123');

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/pagerules/page-123`,
          expect.objectContaining({ method: 'DELETE' })
        );
      });

      test('should list page rules', async () => {
        await api.listPageRules();

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/pagerules`,
          expect.objectContaining({ method: 'GET' })
        );
      });
    });

    describe('Analytics Methods', () => {
      beforeEach(() => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: {} })
        });
      });

      test('should get analytics', async () => {
        const since = '2023-01-01T00:00:00Z';
        const until = '2023-01-02T00:00:00Z';
        
        await api.getAnalytics(since, until);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/analytics/dashboard?since=${since}&until=${until}`,
          expect.objectContaining({ method: 'GET' })
        );
      });

      test('should get firewall events', async () => {
        const since = '2023-01-01T00:00:00Z';
        const until = '2023-01-02T00:00:00Z';
        
        await api.getFirewallEvents(since, until);

        expect(mockFetch).toHaveBeenCalledWith(
          `https://api.cloudflare.com/client/v4/zones/${mockConfig.zoneId}/security/events?since=${since}&until=${until}`,
          expect.objectContaining({ method: 'GET' })
        );
      });
    });
  });

  describe('cloudflareSettings Configuration', () => {
    test('should have correct security level', () => {
      expect(cloudflareSettings.securityLevel).toBe('high');
    });

    test('should have correct SSL configuration', () => {
      expect(cloudflareSettings.ssl).toEqual({
        mode: 'full_strict',
        minTlsVersion: '1.2',
        opportunisticEncryption: true,
        alwaysUseHttps: true,
        automaticHttpsRewrites: true
      });
    });

    test('should have valid WAF rules', () => {
      expect(cloudflareSettings.wafRules).toBeInstanceOf(Array);
      expect(cloudflareSettings.wafRules.length).toBeGreaterThan(0);
      
      cloudflareSettings.wafRules.forEach(rule => {
        expect(rule).toHaveProperty('description');
        expect(rule).toHaveProperty('expression');
        expect(rule).toHaveProperty('action');
        expect(typeof rule.description).toBe('string');
        expect(typeof rule.expression).toBe('string');
        expect(['block', 'challenge', 'allow', 'log', 'bypass', 'js_challenge', 'managed_challenge'])
          .toContain(rule.action);
      });
    });

    test('should have valid rate limit rules', () => {
      expect(cloudflareSettings.rateLimitRules).toBeInstanceOf(Array);
      expect(cloudflareSettings.rateLimitRules.length).toBeGreaterThan(0);
      
      cloudflareSettings.rateLimitRules.forEach(rule => {
        expect(rule).toHaveProperty('threshold');
        expect(rule).toHaveProperty('period');
        expect(rule).toHaveProperty('action');
        expect(rule).toHaveProperty('match');
        expect(rule).toHaveProperty('description');
        expect(typeof rule.threshold).toBe('number');
        expect(typeof rule.period).toBe('number');
        expect(rule.threshold).toBeGreaterThan(0);
        expect(rule.period).toBeGreaterThan(0);
      });
    });

    test('should have valid page rules', () => {
      expect(cloudflareSettings.pageRules).toBeInstanceOf(Array);
      expect(cloudflareSettings.pageRules.length).toBeGreaterThan(0);
      
      cloudflareSettings.pageRules.forEach(rule => {
        expect(rule).toHaveProperty('targets');
        expect(rule).toHaveProperty('actions');
        expect(rule).toHaveProperty('status');
        expect(rule.targets).toBeInstanceOf(Array);
        expect(rule.actions).toBeInstanceOf(Array);
        expect(['active', 'disabled']).toContain(rule.status);
      });
    });

    test('should have valid performance settings', () => {
      expect(cloudflareSettings.performance).toEqual({
        minify: { css: true, html: true, js: true },
        brotli: true,
        http2: true,
        http3: true,
        ipv6: true,
        websockets: true
      });
    });

    test('should have valid bot management settings', () => {
      expect(cloudflareSettings.botManagement).toEqual({
        fightMode: true
      });
    });

    test('should have valid DDoS protection settings', () => {
      expect(cloudflareSettings.ddosProtection).toEqual({
        l3l4: true,
        l7: true,
        sensitivityLevel: 'high'
      });
    });
  });

  describe('environmentConfigs', () => {
    test('should have development config', () => {
      expect(environmentConfigs.development).toEqual({
        securityLevel: 'medium',
        rateLimitMultiplier: 10,
        enableWAF: false
      });
    });

    test('should have staging config', () => {
      expect(environmentConfigs.staging).toEqual({
        securityLevel: 'high',
        rateLimitMultiplier: 2,
        enableWAF: true
      });
    });

    test('should have production config', () => {
      expect(environmentConfigs.production).toEqual({
        securityLevel: 'under_attack',
        rateLimitMultiplier: 1,
        enableWAF: true
      });
    });

    test('should have valid security levels', () => {
      Object.values(environmentConfigs).forEach(config => {
        expect(['off', 'essentially_off', 'low', 'medium', 'high', 'under_attack'])
          .toContain(config.securityLevel);
        expect(typeof config.rateLimitMultiplier).toBe('number');
        expect(config.rateLimitMultiplier).toBeGreaterThan(0);
        expect(typeof config.enableWAF).toBe('boolean');
      });
    });
  });

  describe('setupCloudflare function', () => {
    let consoleSpy: jest.SpyInstance;
    const mockConfig: CloudflareConfig = {
      zoneId: 'test-zone',
      apiToken: 'test-token',
      domain: 'test.com'
    };

    beforeEach(() => {
      consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      jest.spyOn(console, 'warn').mockImplementation();
      jest.spyOn(console, 'error').mockImplementation();
      
      // Reset mocks for this describe block
      mockFetch.mockReset();
    });

    afterEach(() => {
      consoleSpy.mockRestore();
      jest.restoreAllMocks();
    });

    test('should complete setup successfully', async () => {
      createSuccessfulSetupMocks();
      
      await setupCloudflare(mockConfig);
      
      expect(consoleSpy).toHaveBeenCalledWith('🔄 Setting up Cloudflare configuration...');
      expect(consoleSpy).toHaveBeenCalledWith('\n🎉 Cloudflare setup complete!');
    });

    test('should handle API errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('API Error'));
      
      await expect(setupCloudflare(mockConfig)).rejects.toThrow('API Error');
      expect(console.error).toHaveBeenCalledWith('❌ Cloudflare setup failed:', 'API Error');
    });

    test('should make all required API calls', async () => {
      createSuccessfulSetupMocks();
      
      await setupCloudflare(mockConfig);
      
      // Verify minimum number of API calls were made 
      // (13 settings + 3 list operations + 12 rule operations = ~28 calls)
      expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(25);
      
      // Verify specific endpoint calls
      const calls = mockFetch.mock.calls;
      const urls = calls.map(call => call[0]);
      
      expect(urls.some(url => url.includes('/settings/security_level'))).toBe(true);
      expect(urls.some(url => url.includes('/settings/ssl'))).toBe(true);
      expect(urls.some(url => url.includes('/firewall/rules'))).toBe(true);
      expect(urls.some(url => url.includes('/rate_limits'))).toBe(true);
      expect(urls.some(url => url.includes('/pagerules'))).toBe(true);
    });

    test('should handle partial failures and continue', async () => {
      // Mock sequence of calls - some succeed, some fail
      // Settings updates (13 calls) - all succeed
      Array(13).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true, 
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });
      
      // List firewall rules succeeds - return empty array
      mockFetch.mockResolvedValueOnce({
        ok: true, 
        json: jest.fn().mockResolvedValue({ success: true, result: [] })
      });
      
      // Create firewall rules - first one fails, others succeed
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: jest.fn().mockResolvedValue({ 
          errors: [{ code: 1001, message: 'Test error' }] 
        })
      });
      
      // Remaining firewall rule creations succeed
      Array(4).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true, 
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });
      
      // List rate limits and page rules succeed
      mockFetch.mockResolvedValueOnce({
        ok: true, 
        json: jest.fn().mockResolvedValue({ success: true, result: [] })
      });
      
      // Rate limit rule creations succeed
      Array(4).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true, 
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });
      
      // List page rules succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true, 
        json: jest.fn().mockResolvedValue({ success: true, result: [] })
      });
      
      // Page rule creations succeed
      Array(3).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true, 
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });

      await setupCloudflare(mockConfig);
      
      expect(console.warn).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('\n🎉 Cloudflare setup complete!');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle empty rate limit rules array', () => {
      const emptySettings = { ...cloudflareSettings, rateLimitRules: [] };
      expect(emptySettings.rateLimitRules).toEqual([]);
    });

    test('should handle complex action objects in rate limits', () => {
      const complexAction = { mode: 'block' as const, timeout: 3600 };
      const rule: RateLimitRule = {
        threshold: 10,
        period: 60,
        action: complexAction,
        match: { request: { url: 'test.com/*' } },
        description: 'Complex action rule'
      };
      
      expect(rule.action).toEqual(complexAction);
    });

    test('should handle optional properties correctly', () => {
      const minimalConfig: CloudflareConfig = {
        zoneId: 'zone',
        apiToken: 'token',
        domain: 'test.com'
      };
      
      expect(minimalConfig.subdomain).toBeUndefined();
      
      const api = new CloudflareAPI(minimalConfig);
      expect(api).toBeInstanceOf(CloudflareAPI);
    });

    test('should validate rate limit match patterns', () => {
      cloudflareSettings.rateLimitRules.forEach(rule => {
        expect(rule.match).toHaveProperty('request');
        if (rule.match.request.url) {
          expect(typeof rule.match.request.url).toBe('string');
        }
        if (rule.match.request.methods) {
          expect(Array.isArray(rule.match.request.methods)).toBe(true);
          rule.match.request.methods.forEach(method => {
            expect(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']).toContain(method);
          });
        }
      });
    });

    test('should handle firewall rule expressions correctly', () => {
      cloudflareSettings.wafRules.forEach(rule => {
        expect(typeof rule.expression).toBe('string');
        expect(rule.expression.length).toBeGreaterThan(0);
        // Validate that expressions contain valid Cloudflare rule language syntax
        if (rule.expression.includes('http.')) {
          expect(rule.expression).toMatch(/http\.(request|user_agent)/);
        }
      });
    });

    test('should handle page rule target values correctly', () => {
      cloudflareSettings.pageRules.forEach(rule => {
        rule.targets.forEach(target => {
          expect(target.target).toBe('url');
          expect(['matches', 'contains']).toContain(target.constraint.operator);
          expect(typeof target.constraint.value).toBe('string');
          expect(target.constraint.value.length).toBeGreaterThan(0);
        });
      });
    });
  });

  describe('Type Safety and Validation', () => {
    test('should enforce SecurityLevel type constraints', () => {
      const validLevels: SecurityLevel[] = ['off', 'essentially_off', 'low', 'medium', 'high', 'under_attack'];
      validLevels.forEach(level => {
        expect(typeof level).toBe('string');
      });
    });

    test('should enforce SslMode type constraints', () => {
      const validModes: SslMode[] = ['off', 'flexible', 'full', 'full_strict'];
      validModes.forEach(mode => {
        expect(typeof mode).toBe('string');
      });
    });

    test('should enforce MinifySetting structure', () => {
      const minifyConfig: MinifySetting = { css: true, html: false, js: true };
      expect(typeof minifyConfig.css).toBe('boolean');
      expect(typeof minifyConfig.html).toBe('boolean');
      expect(typeof minifyConfig.js).toBe('boolean');
    });

    test('should validate firewall rule actions', () => {
      const validActions = ['block', 'challenge', 'allow', 'log', 'bypass', 'js_challenge', 'managed_challenge'];
      cloudflareSettings.wafRules.forEach(rule => {
        expect(validActions).toContain(rule.action);
      });
    });

    test('should validate rate limit actions', () => {
      const validActions = ['block', 'challenge', 'log', 'js_challenge', 'managed_challenge'];
      cloudflareSettings.rateLimitRules.forEach(rule => {
        if (typeof rule.action === 'string') {
          expect(validActions).toContain(rule.action);
        } else {
          expect(validActions).toContain(rule.action.mode);
        }
      });
    });
  });

  describe('Configuration Consistency', () => {
    test('should have consistent domain references in rate limits', () => {
      const domainPattern = /\*.*\.com/;
      cloudflareSettings.rateLimitRules.forEach(rule => {
        if (rule.match.request.url) {
          expect(rule.match.request.url).toMatch(domainPattern);
        }
      });
    });

    test('should have consistent domain references in page rules', () => {
      const httpsPattern = /^https:\/\//;
      cloudflareSettings.pageRules.forEach(rule => {
        rule.targets.forEach(target => {
          if (target.constraint.value.includes('your-domain.com')) {
            expect(target.constraint.value).toMatch(httpsPattern);
          }
        });
      });
    });

    test('should have reasonable rate limit thresholds', () => {
      cloudflareSettings.rateLimitRules.forEach(rule => {
        expect(rule.threshold).toBeGreaterThan(0);
        expect(rule.threshold).toBeLessThan(10000); // Reasonable upper bound
        expect(rule.period).toBeGreaterThan(0);
        expect(rule.period).toBeLessThanOrEqual(86400); // Maximum 24 hours
      });
    });

    test('should have reasonable page rule priorities', () => {
      cloudflareSettings.pageRules.forEach(rule => {
        if (rule.priority) {
          expect(rule.priority).toBeGreaterThan(0);
          expect(rule.priority).toBeLessThanOrEqual(100); // Cloudflare max priority
        }
      });
    });
  });

  describe('Environment Configuration Logic', () => {
    test('should properly scale rate limits based on environment multiplier', () => {
      const originalRule = cloudflareSettings.rateLimitRules[0];
      const devMultiplier = environmentConfigs.development.rateLimitMultiplier;
      const scaledThreshold = Math.ceil(originalRule.threshold * devMultiplier);
      
      expect(scaledThreshold).toBe(originalRule.threshold * devMultiplier);
      expect(scaledThreshold).toBeGreaterThan(originalRule.threshold);
    });

    test('should handle environment-specific security levels', () => {
      Object.values(environmentConfigs).forEach(config => {
        const validLevels = ['off', 'essentially_off', 'low', 'medium', 'high', 'under_attack'];
        expect(validLevels).toContain(config.securityLevel);
      });
    });

    test('should handle WAF enabling/disabling per environment', () => {
      expect(environmentConfigs.development.enableWAF).toBe(false);
      expect(environmentConfigs.staging.enableWAF).toBe(true);
      expect(environmentConfigs.production.enableWAF).toBe(true);
    });
  });

  describe('API Response Handling', () => {
    let api: CloudflareAPI;
    const mockConfig: CloudflareConfig = {
      zoneId: 'test-zone',
      apiToken: 'test-token',
      domain: 'test.com'
    };

    beforeEach(() => {
      api = new CloudflareAPI(mockConfig);
      // Reset mocks for this describe block
      mockFetch.mockReset();
    });

    test('should handle partial success responses', async () => {
      const partialSuccessResponse = {
        success: false,
        errors: [{ code: 1003, message: 'Invalid zone' }],
        messages: [],
        result: null
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: jest.fn().mockResolvedValueOnce(partialSuccessResponse)
      });

      await expect(api.updateSecurityLevel('high'))
        .rejects.toThrow('Cloudflare API error (400 Bad Request): Code: 1003, Message: Invalid zone');
    });

    test('should handle rate limit exceeded responses', async () => {
      const rateLimitResponse = {
        success: false,
        errors: [{ code: 10013, message: 'Rate limit exceeded' }]
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        json: jest.fn().mockResolvedValueOnce(rateLimitResponse)
      });

      await expect(api.listFirewallRules())
        .rejects.toThrow('Cloudflare API error (429 Too Many Requests): Code: 10013, Message: Rate limit exceeded');
    });

    test('should handle malformed JSON responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: jest.fn().mockRejectedValueOnce(new Error('Invalid JSON'))
      });

      await expect(api.getAnalytics('2023-01-01', '2023-01-02'))
        .rejects.toThrow('Invalid JSON');
    });
  });

  describe('Setup Function Edge Cases', () => {
    const mockConfig: CloudflareConfig = {
      zoneId: 'test-zone',
      apiToken: 'test-token',
      domain: 'test.com'
    };

    beforeEach(() => {
      jest.spyOn(console, 'log').mockImplementation();
      jest.spyOn(console, 'warn').mockImplementation();
      jest.spyOn(console, 'error').mockImplementation();
      
      // Reset mocks for this describe block
      mockFetch.mockReset();
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('should handle existing rules correctly', async () => {
      // Mock responses for existing rules
      // Settings updates (13 calls)
      Array(13).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });

      // List firewall rules - return existing rule
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({ 
          success: true, 
          result: [{
            id: 'existing-rule-1',
            description: 'Block SQL Injection attempts (body & query)'
          }]
        })
      });

      // Update existing rule
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true })
      });

      // Remaining firewall rule operations
      Array(4).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });

      // List rate limits
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true, result: [] })
      });

      // Rate limit operations
      Array(4).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });

      // List page rules
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({ success: true, result: [] })
      });

      // Page rule operations
      Array(3).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });

      await setupCloudflare(mockConfig);
      
      expect(console.log).toHaveBeenCalledWith('✅ Updated firewall rule: Block SQL Injection attempts (body & query)');
    });

    test('should handle rule creation failures gracefully', async () => {
      // Mock successful settings updates
      Array(13).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true })
        });
      });
      
      // List firewall rules - successful with empty result
      mockFetch.mockResolvedValueOnce({
        ok: true, 
        json: jest.fn().mockResolvedValue({ success: true, result: [] })
      });
      
      // First firewall rule creation fails
      mockFetch.mockResolvedValueOnce({
        ok: false, 
        status: 400, 
        statusText: 'Bad Request', 
        json: jest.fn().mockResolvedValue({ 
          errors: [{ code: 1001, message: 'Rule creation failed' }] 
        })
      });
      
      // Remaining operations succeed
      Array(15).fill(null).forEach(() => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ success: true, result: [] })
        });
      });

      await setupCloudflare(mockConfig);
      
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Failed to create/update firewall rule')
      );
    });
  });

  describe('String Templates and Scripts', () => {
    test('should have valid bash script syntax in setup script', () => {
      const { cloudflareSetupScript } = require('../../config/cloudflare');
      
      expect(cloudflareSetupScript).toContain('#!/bin/bash');
      expect(cloudflareSetupScript).toContain('CLOUDFLARE_API_TOKEN');
      expect(cloudflareSetupScript).toContain('CLOUDFLARE_ZONE_ID');
      expect(cloudflareSetupScript).toContain('DOMAIN');
      expect(cloudflareSetupScript).toContain('setupCloudflare(config)');
    });

    test('should contain proper environment variable checks', () => {
      const { cloudflareSetupScript } = require('../../config/cloudflare');
      
      expect(cloudflareSetupScript).toContain('if [ -z "$CLOUDFLARE_API_TOKEN" ]');
      expect(cloudflareSetupScript).toContain('if [ -z "$CLOUDFLARE_ZONE_ID" ]');
      expect(cloudflareSetupScript).toContain('if [ -z "$DOMAIN" ]');
    });

    test('should include error handling in script', () => {
      const { cloudflareSetupScript } = require('../../config/cloudflare');
      
      expect(cloudflareSetupScript).toContain('exit 1');
      expect(cloudflareSetupScript).toContain('process.exit(1)');
    });
  });

  describe('Module Exports', () => {
    test('should export all required components', () => {
      const module = require('../../config/cloudflare');
      
      expect(module).toHaveProperty('CloudflareAPI');
      expect(module).toHaveProperty('cloudflareSettings');
      expect(module).toHaveProperty('setupCloudflare');
      expect(module).toHaveProperty('environmentConfigs');
      expect(module).toHaveProperty('cloudflareSetupScript');
      expect(module.default).toHaveProperty('cloudflareSettings');
      expect(module.default).toHaveProperty('CloudflareAPI');
    });

    test('should have correct function signatures', () => {
      expect(typeof CloudflareAPI).toBe('function');
      expect(typeof setupCloudflare).toBe('function');
      expect(typeof cloudflareSettings).toBe('object');
      expect(typeof environmentConfigs).toBe('object');
    });
  });

  describe('Performance and Memory', () => {
    test('should not create excessive objects during configuration', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Create multiple instances
      for (let i = 0; i < 100; i++) {
        new CloudflareAPI({
          zoneId: `zone-${i}`,
          apiToken: `token-${i}`,
          domain: `domain-${i}.com`
        });
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Should not use excessive memory (less than 10MB for 100 instances)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    test('should handle large configuration objects efficiently', () => {
      const start = performance.now();
      
      // Access all configuration properties
      Object.keys(cloudflareSettings).forEach(key => {
        const value = (cloudflareSettings as any)[key];
        if (Array.isArray(value)) {
          value.forEach(item => JSON.stringify(item));
        }
      });
      
      const end = performance.now();
      const duration = end - start;
      
      // Should complete in reasonable time (less than 100ms)
      expect(duration).toBeLessThan(100);
    });
  });
});