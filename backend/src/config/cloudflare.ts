// backend/src/config/cloudflare.ts
// Cloudflare configuration and management

export interface CloudflareConfig {
  zoneId: string;
  apiToken: string;
  domain: string;
  subdomain?: string;
}

export type RateLimitAction = 'block' | 'challenge' | 'log' | 'js_challenge' | 'managed_challenge'; // Added managed_challenge
export type RateLimitMatch = {
  request: {
    url?: string; // e.g., "your-domain.com/api/*"
    methods?: string[]; // e.g., ["GET", "POST"]
    schemes?: string[]; // e.g., ["HTTP", "HTTPS"]
  };
  response?: {
    status?: number[]; // e.g., [403, 404]
    headers?: Array<{
      name: string;
      operator: 'eq' | 'ne' | 'contains' | 'starts_with' | 'ends_with';
      value: string;
    }>;
  };
  // More complex match properties can exist: headers, response.headers, response.status
  // For simplicity, we'll focus on request.url for now, which is common.
};

export interface RateLimitRule {
  id?: string;
  threshold: number; // Number of requests
  period: number; // Time in seconds (e.g., 60 for 1 minute)
  action: RateLimitAction | { mode: RateLimitAction; timeout?: number; response?: any };
  match: RateLimitMatch; // Structured match object
  description: string;
  // Optional: bypass, response, disabled
}

export type FirewallRuleAction = 'block' | 'challenge' | 'allow' | 'log' | 'bypass' | 'js_challenge' | 'managed_challenge'; // Added js_challenge, managed_challenge
export interface FirewallRule {
  id?: string;
  expression: string; // Cloudflare Rule Language expression
  action: FirewallRuleAction;
  description: string;
  priority?: number;
  paused?: boolean; // Rule status: active/disabled
}

export interface PageRule {
  id?: string;
  targets: Array<{
    target: 'url';
    constraint: {
      operator: 'matches' | 'contains'; // 'matches' for wildcard, 'contains' for substring
      value: string;
    };
  }>;
  actions: Array<{
    id: string; // Corresponds to Cloudflare setting ID (e.g., 'cache_level', 'security_level')
    value?: any; // Value for the action
  }>;
  priority?: number; // Higher number = higher priority
  status: 'active' | 'disabled';
}

// Helper types for Cloudflare API settings (values are specific strings)
export type SecurityLevel = 'off' | 'essentially_off' | 'low' | 'medium' | 'high' | 'under_attack';
export type SslMode = 'off' | 'flexible' | 'full' | 'full_strict';
export type MinifySetting = { css: boolean; html: boolean; js: boolean };

/**
 * Cloudflare Configuration for Koutu Fashion API
 *
 * NOTE: These settings primarily define the *desired state*.
 * The `setupCloudflare` function will use the Cloudflare API
 * to attempt to apply these settings to your zone.
 * Not all settings here directly map to a single API call; some are
 * part of broader settings updates.
 */
export const cloudflareSettings = {
  // Global Zone Settings
  securityLevel: 'high' as SecurityLevel, // Will be set via API
  ssl: {
    mode: 'full_strict' as SslMode, // Will be set via API
    minTlsVersion: '1.2', // Requires separate API call for 'min_tls_version' setting
    opportunisticEncryption: true, // Requires separate API call for 'opportunistic_encryption' setting
    alwaysUseHttps: true, // Requires separate API call for 'always_use_https' setting
    automaticHttpsRewrites: true // Requires separate API call for 'automatic_https_rewrites' setting
  },

  // WAF (Web Application Firewall) Custom Rules - these are not the Managed WAF ruleset.
  // These are custom Firewall Rules (previously called "WAF Custom Rules" in UI)
  wafRules: [
    {
      description: 'Block SQL Injection attempts (body & query)',
      expression: '(http.request.body contains "union select") or (http.request.body contains "drop table") or (http.request.uri.query contains "1=1") or (http.request.uri.query contains "union select")',
      action: 'block'
    },
    {
      description: 'Block XSS attempts (body & query)',
      expression: '(http.request.body contains "<script>") or (http.request.body contains "javascript:") or (http.request.uri.query contains "alert(") or (http.request.uri.query contains "<script>")',
      action: 'block'
    },
    {
      description: 'Block path traversal attempts',
      expression: '(http.request.uri.path contains "../") or (http.request.uri.path contains "..\\") or (http.request.uri.query contains "../")',
      action: 'block'
    },
    {
      description: 'Challenge common admin panel access attempts',
      expression: '(http.request.uri.path contains "/admin") or (http.request.uri.path contains "/wp-admin") or (http.request.uri.path contains "/phpmyadmin")',
      action: 'challenge' // Better to challenge than block outright for common paths
    },
    {
      description: 'Challenge suspicious user agents (bots, crawlers, spiders)',
      expression: '(http.user_agent contains "bot") or (http.user_agent contains "crawler") or (http.user_agent contains "spider")',
      action: 'js_challenge'
    }
  ] as FirewallRule[],

  // Rate Limiting Rules (API uses /rate_limits endpoint)
  // The 'match' property here needs to be more structured for the API
  rateLimitRules: [
    {
      threshold: 100,
      period: 60,
      action: 'block',
      match: {
        request: {
          url: `*${process.env.DOMAIN || 'your-domain.com'}/*`, // General rate limit for entire domain
          methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] // Apply to all common methods
        }
      },
      description: 'General API rate limit - 100 requests per minute per IP'
    },
    {
      threshold: 10,
      period: 60,
      action: 'block',
      match: {
        request: {
          url: `*${process.env.DOMAIN || 'your-domain.com'}/api/v1/auth/*`, // More specific URL match
          methods: ['POST', 'PUT'] // Typically for login/registration
        }
      },
      description: 'Authentication endpoints - 10 requests per minute per IP'
    },
    {
      threshold: 20,
      period: 60,
      action: 'block',
      match: {
        request: {
          url: `*${process.env.DOMAIN || 'your-domain.com'}/api/v1/files/*`,
          methods: ['POST', 'PUT'] // For file uploads
        }
      },
      description: 'File upload endpoints - 20 requests per minute per IP'
    },
    {
      threshold: 50,
      period: 60,
      action: 'challenge',
      match: {
        request: {
          url: `*${process.env.DOMAIN || 'your-domain.com'}/api/v1/images/*`,
          methods: ['GET'] // For image downloads
        }
      },
      description: 'Image endpoints - 50 requests per minute, then challenge'
    }
  ] as RateLimitRule[],

  // Page Rules for caching and optimization
  // NOTE: Page Rule values for `targets.constraint.value` must be a full URL pattern,
  // including scheme and hostname, and can use wildcards.
  pageRules: [
    {
      targets: [{
        target: 'url' as const,
        constraint: {
          operator: 'matches' as const,
          value: 'https://your-domain.com/api/v1/files/*.jpg' // Full URL pattern expected
        }
      }],
      actions: [
        { id: 'cache_level', value: 'cache_everything' },
        { id: 'edge_cache_ttl', value: 86400 }, // 24 hours
        { id: 'browser_cache_ttl', value: 31536000 } // 1 year
      ],
      priority: 1,
      status: 'active' as const
    },
    {
      targets: [{
        target: 'url' as const,
        constraint: {
          operator: 'matches' as const,
          value: 'https://your-domain.com/api/v1/files/*.png' // Full URL pattern expected
        }
      }],
      actions: [
        { id: 'cache_level', value: 'cache_everything' },
        { id: 'edge_cache_ttl', value: 86400 },
        { id: 'browser_cache_ttl', value: 31536000 }
      ],
      priority: 2,
      status: 'active' as const
    },
    {
      targets: [{
        target: 'url' as const,
        constraint: {
          operator: 'matches' as const,
          value: 'https://your-domain.com/api/v1/auth/*' // Full URL pattern expected
        }
      }],
      actions: [
        { id: 'cache_level', value: 'bypass' }, // Do not cache auth endpoints
        { id: 'security_level', value: 'high' } // Apply high security to auth endpoints
      ],
      priority: 3,
      status: 'active' as const
    }
  ],

  // Performance optimization (these map to individual zone settings API calls)
  performance: {
    minify: {
      css: true,
      html: true,
      js: true
    },
    brotli: true,
    http2: true,
    http3: true,
    ipv6: true,
    websockets: true
  },

  // Bot management (these map to individual zone settings API calls or specific rules)
  // Note: 'Bot Fight Mode' is a simpler version of bot management, directly configurable
  // on Free/Pro plans. The API for granular bot management (score, etc.) is more complex
  // and often requires Enterprise plan or specific rulesets.
  // For `botManagement.fightMode`, it's a simple toggle.
  botManagement: {
    fightMode: true // This maps to the 'bot_management' setting, value 'on'/'off'
    // sessionVerification: true, // No direct single API setting for this
    // enableJsDetection: true, // No direct single API setting for this
    // challengePassage: 86400 // No direct single API setting for this
  },

  // DDoS protection (general zone settings; more advanced is via rulesets API for Enterprise)
  ddosProtection: {
    l3l4: true, // This is often a default and not directly configurable by a simple setting
    l7: true,   // This is often a default and not directly configurable by a simple setting
    sensitivityLevel: 'high' // Maps to 'ddos_attack_protection' setting or a rule override
  }
};

/**
 * Cloudflare API Client
 */
export class CloudflareAPI {
  private config: CloudflareConfig;
  private baseUrl = 'https://api.cloudflare.com/client/v4';

  constructor(config: CloudflareConfig) {
    this.config = config;
  }

  private async makeRequest(method: string, endpoint: string, data?: any) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${this.config.apiToken}`,
      'Content-Type': 'application/json'
    };

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: data ? JSON.stringify(data) : undefined
      });

      const responseBody = await response.json();

      if (!response.ok) {
        // Cloudflare API errors often come with a 'errors' array
        const errorMessages = responseBody.errors ?
          responseBody.errors.map((err: any) => `Code: ${err.code}, Message: ${err.message}`).join('; ') :
          'No specific error message from Cloudflare.';
        throw new Error(`Cloudflare API error (${response.status} ${response.statusText}): ${errorMessages}`);
      }

      return responseBody;
    } catch (error: any) {
      console.error(`Error making Cloudflare API request to ${url}:`, error.message);
      throw error; // Re-throw the error for the caller to handle
    }
  }

  // Zone Settings Management
  // Many general settings are updated via PATCH /zones/{zone_id}/settings/{setting_id}
  async updateZoneSetting(settingId: string, value: any) {
    return this.makeRequest('PATCH', `/zones/${this.config.zoneId}/settings/${settingId}`, { value });
  }

  async updateSecurityLevel(level: SecurityLevel) {
    return this.updateZoneSetting('security_level', level);
  }

  async updateSSLMode(mode: SslMode) {
    return this.updateZoneSetting('ssl', { value: mode }); // SSL mode is set as a value under 'ssl' setting
  }

  async updateMinTlsVersion(version: string) {
    return this.updateZoneSetting('min_tls_version', version);
  }

  async updateOpportunisticEncryption(enabled: boolean) {
    return this.updateZoneSetting('opportunistic_encryption', enabled ? 'on' : 'off');
  }

  async updateAlwaysUseHttps(enabled: boolean) {
    return this.updateZoneSetting('always_use_https', enabled ? 'on' : 'off');
  }

  async updateAutomaticHttpsRewrites(enabled: boolean) {
    return this.updateZoneSetting('automatic_https_rewrites', enabled ? 'on' : 'off');
  }

  async updateMinify(minifyConfig: MinifySetting) {
    return this.updateZoneSetting('minify', { value: minifyConfig });
  }

  async updateBrotli(enabled: boolean) {
    return this.updateZoneSetting('brotli', enabled ? 'on' : 'off');
  }

  async updateHttp2(enabled: boolean) {
    return this.updateZoneSetting('http2', enabled ? 'on' : 'off');
  }

  async updateHttp3(enabled: boolean) {
    return this.updateZoneSetting('http3', enabled ? 'on' : 'off');
  }

  async updateIpv6(enabled: boolean) {
    return this.updateZoneSetting('ipv6', enabled ? 'on' : 'off');
  }

  async updateWebsockets(enabled: boolean) {
    return this.updateZoneSetting('websockets', enabled ? 'on' : 'off');
  }

  async updateBotFightMode(enabled: boolean) {
    // This setting's value is 'on' or 'off'
    return this.updateZoneSetting('bot_management', enabled ? 'on' : 'off');
  }

  // Note: DDoS protection sensitivity is part of the 'ddos_attack_protection' setting,
  // which might be an Enterprise feature or managed via Rulesets API for more granularity.
  // For simpler cases, the general security_level might influence this.
  // We'll leave the direct l3l4/l7 as conceptual for now as they are often defaults
  // or part of more complex ruleset configurations, not simple on/off settings.

  async purgeCache(files?: string[]) {
    return this.makeRequest('POST', `/zones/${this.config.zoneId}/purge_cache`,
      files ? { files } : { purge_everything: true }
    );
  }

  // Firewall Rules Management (Ruleset Engine based)
  // Cloudflare's Firewall Rules API might be under '/filters' and '/firewall/rules'
  // or the newer Ruleset Engine. For simplicity and common use, let's stick to
  // the `/firewall/rules` endpoint if it's still suitable for custom rules.
  // The structure expected for POST is:
  // {
  //   "action": "block",
  //   "filter": { "expression": "...", "description": "..." },
  //   "description": "..."
  // }
  async createFirewallRule(rule: Omit<FirewallRule, 'id'>) {
    return this.makeRequest('POST', `/zones/${this.config.zoneId}/firewall/rules`, {
      action: rule.action,
      filter: {
        expression: rule.expression,
        description: rule.description, // Filter description
        paused: rule.paused // Filter can be paused
      },
      description: rule.description, // Rule description
      priority: rule.priority,
      paused: rule.paused // Rule can be paused
    });
  }

  async updateFirewallRule(ruleId: string, rule: Partial<FirewallRule>) {
    // Note: When updating, `filter` object structure might need to be re-sent correctly.
    // Cloudflare API docs recommend getting the existing rule and patching relevant fields.
    // For simplicity, this assumes direct patch, but actual API might need {filter: {expression: ...}}
    return this.makeRequest('PUT', `/zones/${this.config.zoneId}/firewall/rules/${ruleId}`, rule);
  }

  async deleteFirewallRule(ruleId: string) {
    return this.makeRequest('DELETE', `/zones/${this.config.zoneId}/firewall/rules/${ruleId}`);
  }

  async listFirewallRules() {
    return this.makeRequest('GET', `/zones/${this.config.zoneId}/firewall/rules`);
  }

  // Rate Limiting Management
  async createRateLimit(rule: Omit<RateLimitRule, 'id'>) {
    // Cloudflare Rate Limit API has a specific structure for 'match' and 'action'
    return this.makeRequest('POST', `/zones/${this.config.zoneId}/rate_limits`, {
      threshold: rule.threshold,
      period: rule.period,
      action: {
        mode: rule.action,
        // timeout applies only to 'block' actions, otherwise Cloudflare uses zone's challenge passage
        timeout: rule.action === 'block' ? 86400 : undefined
        // response: {} // Custom response if needed
      },
      match: rule.match, // 'match' is now directly passed as RateLimitMatch
      description: rule.description,
      // disabled: false // Default to active
    });
  }

  async updateRateLimit(ruleId: string, rule: Partial<RateLimitRule>) {
    return this.makeRequest('PUT', `/zones/${this.config.zoneId}/rate_limits/${ruleId}`, rule);
  }

  async deleteRateLimit(ruleId: string) {
    return this.makeRequest('DELETE', `/zones/${this.config.zoneId}/rate_limits/${ruleId}`);
  }

  async listRateLimits() {
    return this.makeRequest('GET', `/zones/${this.config.zoneId}/rate_limits`);
  }

  // Page Rules Management
  async createPageRule(rule: Omit<PageRule, 'id'>) {
    return this.makeRequest('POST', `/zones/${this.config.zoneId}/pagerules`, rule);
  }

  async updatePageRule(ruleId: string, rule: Partial<PageRule>) {
    return this.makeRequest('PATCH', `/zones/${this.config.zoneId}/pagerules/${ruleId}`, rule);
  }

  async deletePageRule(ruleId: string) {
    return this.makeRequest('DELETE', `/zones/${this.config.zoneId}/pagerules/${ruleId}`);
  }

  async listPageRules() {
    return this.makeRequest('GET', `/zones/${this.config.zoneId}/pagerules`);
  }

  // Analytics
  async getAnalytics(since: string, until: string) {
    return this.makeRequest('GET',
      `/zones/${this.config.zoneId}/analytics/dashboard?since=${since}&until=${until}`
    );
  }

  async getFirewallEvents(since: string, until: string) {
    return this.makeRequest('GET',
      `/zones/${this.config.zoneId}/security/events?since=${since}&until=${until}`
    );
  }
}

/**
 * Setup script for initial Cloudflare configuration
 * This script is intended to be run ONCE or whenever significant
 * Cloudflare settings need to be applied/synced.
 */
export const setupCloudflare = async (config: CloudflareConfig) => {
  const cf = new CloudflareAPI(config);

  console.log('🔄 Setting up Cloudflare configuration...');

  try {
    // 1. Update core security and SSL settings
    await cf.updateSecurityLevel(cloudflareSettings.securityLevel);
    console.log(`✅ Security level set to ${cloudflareSettings.securityLevel}`);

    await cf.updateSSLMode(cloudflareSettings.ssl.mode);
    console.log(`✅ SSL mode set to ${cloudflareSettings.ssl.mode}`);

    await cf.updateMinTlsVersion(cloudflareSettings.ssl.minTlsVersion);
    console.log(`✅ Minimum TLS version set to ${cloudflareSettings.ssl.minTlsVersion}`);

    await cf.updateOpportunisticEncryption(cloudflareSettings.ssl.opportunisticEncryption);
    console.log(`✅ Opportunistic Encryption: ${cloudflareSettings.ssl.opportunisticEncryption ? 'on' : 'off'}`);

    await cf.updateAlwaysUseHttps(cloudflareSettings.ssl.alwaysUseHttps);
    console.log(`✅ Always Use HTTPS: ${cloudflareSettings.ssl.alwaysUseHttps ? 'on' : 'off'}`);

    await cf.updateAutomaticHttpsRewrites(cloudflareSettings.ssl.automaticHttpsRewrites);
    console.log(`✅ Automatic HTTPS Rewrites: ${cloudflareSettings.ssl.automaticHttpsRewrites ? 'on' : 'off'}`);

    // 2. Update performance settings
    await cf.updateMinify(cloudflareSettings.performance.minify);
    console.log('✅ Minification (JS, CSS, HTML) configured.');

    await cf.updateBrotli(cloudflareSettings.performance.brotli);
    console.log(`✅ Brotli compression: ${cloudflareSettings.performance.brotli ? 'on' : 'off'}`);

    await cf.updateHttp2(cloudflareSettings.performance.http2);
    console.log(`✅ HTTP/2: ${cloudflareSettings.performance.http2 ? 'on' : 'off'}`);

    await cf.updateHttp3(cloudflareSettings.performance.http3);
    console.log(`✅ HTTP/3: ${cloudflareSettings.performance.http3 ? 'on' : 'off'}`);

    await cf.updateIpv6(cloudflareSettings.performance.ipv6);
    console.log(`✅ IPv6: ${cloudflareSettings.performance.ipv6 ? 'on' : 'off'}`);

    await cf.updateWebsockets(cloudflareSettings.performance.websockets);
    console.log(`✅ WebSockets: ${cloudflareSettings.performance.websockets ? 'on' : 'off'}`);

    // 3. Update Bot Management settings
    await cf.updateBotFightMode(cloudflareSettings.botManagement.fightMode);
    console.log(`✅ Bot Fight Mode: ${cloudflareSettings.botManagement.fightMode ? 'on' : 'off'}`);


    // 4. Create/Update firewall rules
    console.log('\n--- Configuring Cloudflare Firewall Rules ---');
    const existingFirewallRules = (await cf.listFirewallRules()).result;
    for (const rule of cloudflareSettings.wafRules) {
      const existingRule = existingFirewallRules.find((r: any) => r.description === rule.description);
      try {
        if (existingRule) {
          await cf.updateFirewallRule(existingRule.id, {
            expression: rule.expression,
            action: rule.action,
            description: rule.description,
            priority: rule.priority,
            paused: rule.paused
          });
          console.log(`✅ Updated firewall rule: ${rule.description}`);
        } else {
          await cf.createFirewallRule(rule);
          console.log(`✅ Created firewall rule: ${rule.description}`);
        }
      } catch (error: any) {
        // Log more specific error from Cloudflare if available
        const errorDetail = error.message || 'unknown error';
        console.warn(`⚠️ Failed to create/update firewall rule "${rule.description}": ${errorDetail}`);
      }
    }

    // 5. Create/Update rate limiting rules
    console.log('\n--- Configuring Cloudflare Rate Limits ---');
    const existingRateLimits = (await cf.listRateLimits()).result;
    for (const rule of cloudflareSettings.rateLimitRules) {
      const existingRule = existingRateLimits.find((r: any) => r.description === rule.description);
      try {
        // Note: For rate limits, `match.request.url` can be tricky to compare exactly.
        // Relying on description for idempotency.
        if (existingRule) {
          await cf.updateRateLimit(existingRule.id, {
            threshold: rule.threshold,
            period: rule.period,
            action: typeof rule.action === 'string' ? rule.action : rule.action.mode,
            match: rule.match,
            description: rule.description
          });
          console.log(`✅ Updated rate limit: ${rule.description}`);
        } else {
          await cf.createRateLimit(rule);
          console.log(`✅ Created rate limit: ${rule.description}`);
        }
      } catch (error: any) {
        const errorDetail = error.message || 'unknown error';
        console.warn(`⚠️ Failed to create/update rate limit "${rule.description}": ${errorDetail}`);
      }
    }

    // 6. Create/Update page rules
    console.log('\n--- Configuring Cloudflare Page Rules ---');
    // Page rules API list does not expose `description`, so we'll rely on `targets[0].constraint.value`
    // for finding existing rules. This assumes unique target values for each page rule.
    const existingPageRules = (await cf.listPageRules()).result;
    for (const rule of cloudflareSettings.pageRules) {
      const targetValue = rule.targets[0].constraint.value;
      const existingRule = existingPageRules.find((r: any) =>
        r.targets && r.targets.length > 0 && r.targets[0].constraint.value === targetValue
      );
      try {
        if (existingRule) {
          await cf.updatePageRule(existingRule.id, {
            targets: rule.targets,
            actions: rule.actions,
            priority: rule.priority,
            status: rule.status
          });
          console.log(`✅ Updated page rule for: ${targetValue}`);
        } else {
          await cf.createPageRule(rule);
          console.log(`✅ Created page rule for: ${targetValue}`);
        }
      } catch (error: any) {
        const errorDetail = error.message || 'unknown error';
        console.warn(`⚠️ Failed to create/update page rule for "${targetValue}": ${errorDetail}`);
      }
    }

    console.log('\n🎉 Cloudflare setup complete!');

  } catch (error: any) {
    console.error('❌ Cloudflare setup failed:', error.message);
    throw error;
  }
};

/**
 * Environment-specific configurations for dynamic adjustments
 * This part would typically be used to modify `cloudflareSettings`
 * based on the environment (e.g., in a deployment script or a config loader).
 * It's illustrative; actual application would merge these.
 */
export const environmentConfigs = {
  development: {
    securityLevel: 'medium' as const,
    rateLimitMultiplier: 10, // More lenient for development
    enableWAF: false, // Don't push custom WAF rules in dev
    // You would then modify cloudflareSettings based on this.
    // E.g., in your setup script:
    // if (process.env.NODE_ENV === 'development') {
    //   cloudflareSettings.securityLevel = environmentConfigs.development.securityLevel;
    //   cloudflareSettings.wafRules = []; // Disable custom WAF rules
    //   // Adjust rate limits by multiplying thresholds
    //   cloudflareSettings.rateLimitRules = cloudflareSettings.rateLimitRules.map(rule => ({
    //     ...rule,
    //     threshold: rule.threshold * environmentConfigs.development.rateLimitMultiplier
    //   }));
    // }
  },

  staging: {
    securityLevel: 'high' as const,
    rateLimitMultiplier: 2,
    enableWAF: true
  },

  production: {
    securityLevel: 'under_attack' as const, // Can switch to 'under_attack' if needed
    rateLimitMultiplier: 1,
    enableWAF: true
  }
};

/**
 * Usage example and configuration script
 */
export const cloudflareSetupScript = `#!/bin/bash
# Cloudflare setup script for Koutu Fashion API

echo "🔄 Setting up Cloudflare for Koutu Fashion API..."

# Environment variables needed:
# CLOUDFLARE_API_TOKEN=your_api_token_here
# CLOUDFLARE_ZONE_ID=your_zone_id_here
# DOMAIN=your-domain.com (e.g., myapp.com)
# NODE_ENV=development|staging|production (optional, defaults to development logic)

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "❌ CLOUDFLARE_API_TOKEN environment variable is required"
    exit 1
fi

if [ -z "$CLOUDFLARE_ZONE_ID" ]; then
    echo "❌ CLOUDFLARE_ZONE_ID environment variable is required"
    exit 1
fi

if [ -z "$DOMAIN" ]; then
    echo "❌ DOMAIN environment variable is required (e.g., myapp.com)"
    exit 1
fi

# Set NODE_ENV if not already set, for environment-specific logic in the script
export NODE_ENV=\${NODE_ENV:-development}

# Dynamically adjust settings based on NODE_ENV
# This requires loading the settings and modifying them before passing to setupCloudflare
# For simplicity in a bash script, we'll pass environment variables
# and assume the JS script itself uses process.env.DOMAIN
node -r ts-node/register -e "
  require('dotenv').config(); // Ensure dotenv loads .env files if used
  const { setupCloudflare, cloudflareSettings, environmentConfigs } = require('./backend/src/config/cloudflare');

  const config = {
    apiToken: process.env.CLOUDFLARE_API_TOKEN,
    zoneId: process.env.CLOUDFLARE_ZONE_ID,
    domain: process.env.DOMAIN
  };

  const currentEnv = process.env.NODE_ENV || 'development';
  const envSpecific = environmentConfigs[currentEnv];

  // Apply environment-specific overrides to cloudflareSettings
  if (envSpecific) {
    cloudflareSettings.securityLevel = envSpecific.securityLevel;
    if (!envSpecific.enableWAF) {
      cloudflareSettings.wafRules = []; // Disable custom WAF rules for this env
    }
    cloudflareSettings.rateLimitRules = cloudflareSettings.rateLimitRules.map(rule => ({
      ...rule,
      threshold: Math.ceil(rule.threshold * envSpecific.rateLimitMultiplier) // Adjust threshold
    }));

    // For Page Rules, if you want to swap 'your-domain.com' with the actual domain:
    cloudflareSettings.pageRules.forEach(rule => {
      rule.targets[0].constraint.value = rule.targets[0].constraint.value.replace('your-domain.com', config.domain);
    });
    // Same for rate limit URLs
    cloudflareSettings.rateLimitRules.forEach(rule => {
      rule.match.request.url = rule.match.request.url.replace('your-domain.com', config.domain);
    });

  }

  setupCloudflare(config).then(() => {
    console.log('✅ Cloudflare configuration complete!');
  }).catch(error => {
    console.error('❌ Setup failed:', error);
    process.exit(1);
  });
"

echo "🎉 Cloudflare setup script complete!"
echo ""
echo "Next steps:"
echo "1. Verify firewall rules, rate limits, and page rules in Cloudflare dashboard"
echo "2. Test rate limiting with your API"
echo "3. Monitor security events and analytics"
echo "4. Adjust settings based on usage patterns and threats"
`;

export default {
  cloudflareSettings,
  CloudflareAPI
};