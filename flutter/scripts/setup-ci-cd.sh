#!/bin/bash

# CI/CD Setup Script for Flutter Project
# This script helps set up the CI/CD pipeline with all required configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Flutter CI/CD Setup Script${NC}"
echo -e "${BLUE}==============================${NC}"
echo ""

# Function to print step headers
print_step() {
    echo -e "${BLUE}📋 Step: $1${NC}"
    echo "----------------------------------------"
}

# Function to handle errors
handle_error() {
    echo -e "${RED}❌ Error: $1${NC}"
    exit 1
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to generate base64 encoded file
generate_base64() {
    local file_path="$1"
    local secret_name="$2"
    
    if [[ -f "$file_path" ]]; then
        local encoded=$(base64 -w 0 "$file_path" 2>/dev/null || base64 "$file_path")
        echo -e "${GREEN}✅ Generated base64 for $secret_name${NC}"
        echo -e "${YELLOW}Secret: $secret_name${NC}"
        echo -e "${YELLOW}Value: $encoded${NC}"
        echo ""
    else
        echo -e "${RED}❌ File not found: $file_path${NC}"
    fi
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites"
    
    local missing_tools=()
    
    if ! command_exists flutter; then
        missing_tools+=("flutter")
    fi
    
    if ! command_exists git; then
        missing_tools+=("git")
    fi
    
    if ! command_exists base64; then
        missing_tools+=("base64")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"
        handle_error "Please install the missing tools and try again"
    fi
    
    echo -e "${GREEN}✅ All prerequisites are installed${NC}"
    echo ""
}

# Setup environment files
setup_environment_files() {
    print_step "Setting up environment files"
    
    local env_dir="lib/env"
    
    # Create environment directory if it doesn't exist
    mkdir -p "$env_dir"
    
    # Create development environment file
    if [[ ! -f "$env_dir/env.dev.dart" ]]; then
        cat > "$env_dir/env.dev.dart" << 'EOF'
class Environment {
  static const String name = 'development';
  static const String baseUrl = 'https://dev-api.koutu.com';
  static const String apiKey = 'dev-api-key';
  static const bool enableLogging = true;
  static const bool enableDebugMode = true;
  static const String firebaseProject = 'koutu-dev';
  static const String sentryDsn = 'https://dev-sentry-dsn';
  static const String mixpanelToken = 'dev-mixpanel-token';
}
EOF
        echo -e "${GREEN}✅ Created development environment file${NC}"
    fi
    
    # Create staging environment file
    if [[ ! -f "$env_dir/env.staging.dart" ]]; then
        cat > "$env_dir/env.staging.dart" << 'EOF'
class Environment {
  static const String name = 'staging';
  static const String baseUrl = 'https://staging-api.koutu.com';
  static const String apiKey = 'staging-api-key';
  static const bool enableLogging = true;
  static const bool enableDebugMode = false;
  static const String firebaseProject = 'koutu-staging';
  static const String sentryDsn = 'https://staging-sentry-dsn';
  static const String mixpanelToken = 'staging-mixpanel-token';
}
EOF
        echo -e "${GREEN}✅ Created staging environment file${NC}"
    fi
    
    # Create production environment file
    if [[ ! -f "$env_dir/env.prod.dart" ]]; then
        cat > "$env_dir/env.prod.dart" << 'EOF'
class Environment {
  static const String name = 'production';
  static const String baseUrl = 'https://api.koutu.com';
  static const String apiKey = 'prod-api-key';
  static const bool enableLogging = false;
  static const bool enableDebugMode = false;
  static const String firebaseProject = 'koutu-prod';
  static const String sentryDsn = 'https://prod-sentry-dsn';
  static const String mixpanelToken = 'prod-mixpanel-token';
}
EOF
        echo -e "${GREEN}✅ Created production environment file${NC}"
    fi
    
    # Create default environment file (points to development)
    if [[ ! -f "$env_dir/env.dart" ]]; then
        cp "$env_dir/env.dev.dart" "$env_dir/env.dart"
        echo -e "${GREEN}✅ Created default environment file${NC}"
    fi
    
    echo ""
}

# Setup Android signing configuration
setup_android_signing() {
    print_step "Setting up Android signing configuration"
    
    local android_dir="android"
    local keystore_path="$android_dir/app/keystore.jks"
    local key_properties_path="$android_dir/key.properties"
    
    if [[ ! -f "$keystore_path" ]]; then
        echo -e "${YELLOW}⚠️  Android keystore not found. Creating a debug keystore...${NC}"
        
        # Generate debug keystore
        keytool -genkeypair \
            -alias androiddebugkey \
            -keypass android \
            -keystore "$keystore_path" \
            -storepass android \
            -dname "CN=Android Debug,O=Android,C=US" \
            -keyalg RSA \
            -keysize 2048 \
            -validity 10000 \
            2>/dev/null || echo -e "${RED}❌ Failed to generate debug keystore${NC}"
        
        echo -e "${GREEN}✅ Created debug keystore${NC}"
    fi
    
    # Create key.properties file
    if [[ ! -f "$key_properties_path" ]]; then
        cat > "$key_properties_path" << EOF
storeFile=keystore.jks
storePassword=android
keyAlias=androiddebugkey
keyPassword=android
EOF
        echo -e "${GREEN}✅ Created key.properties file${NC}"
    fi
    
    # Add to .gitignore
    if ! grep -q "key.properties" "$android_dir/.gitignore" 2>/dev/null; then
        echo "key.properties" >> "$android_dir/.gitignore"
        echo -e "${GREEN}✅ Added key.properties to .gitignore${NC}"
    fi
    
    echo ""
}

# Setup iOS signing configuration
setup_ios_signing() {
    print_step "Setting up iOS signing configuration"
    
    local ios_dir="ios"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${YELLOW}ℹ️  iOS signing requires manual configuration:${NC}"
        echo "1. Open ios/Runner.xcworkspace in Xcode"
        echo "2. Configure signing certificates and provisioning profiles"
        echo "3. Export certificates and profiles for CI/CD"
        echo ""
        
        # Create ExportOptions.plist template
        local export_options_path="$ios_dir/ExportOptions.plist"
        if [[ ! -f "$export_options_path" ]]; then
            cat > "$export_options_path" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>compileBitcode</key>
    <false/>
    <key>destination</key>
    <string>export</string>
    <key>method</key>
    <string>app-store</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>com.koutu.app</key>
        <string>Koutu App Store Profile</string>
    </dict>
    <key>signingCertificate</key>
    <string>iOS Distribution</string>
    <key>signingStyle</key>
    <string>manual</string>
    <key>stripSwiftSymbols</key>
    <true/>
    <key>teamID</key>
    <string>YOUR_TEAM_ID</string>
    <key>uploadBitcode</key>
    <false/>
    <key>uploadSymbols</key>
    <true/>
</dict>
</plist>
EOF
            echo -e "${GREEN}✅ Created ExportOptions.plist template${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  iOS signing can only be configured on macOS${NC}"
    fi
    
    echo ""
}

# Setup Firebase configuration
setup_firebase_config() {
    print_step "Setting up Firebase configuration"
    
    # Check if Firebase CLI is installed
    if ! command_exists firebase; then
        echo -e "${YELLOW}⚠️  Firebase CLI not found. Installing...${NC}"
        if command_exists npm; then
            npm install -g firebase-tools
        else
            echo -e "${RED}❌ npm not found. Please install Node.js and npm first${NC}"
            return 1
        fi
    fi
    
    echo -e "${YELLOW}ℹ️  Firebase configuration requires manual setup:${NC}"
    echo "1. Run: firebase login"
    echo "2. Run: firebase projects:list"
    echo "3. Configure your project IDs in environment files"
    echo "4. Download google-services.json and GoogleService-Info.plist"
    echo "5. Place them in android/app/ and ios/Runner/ respectively"
    echo ""
    
    # Create firebase.json if it doesn't exist
    if [[ ! -f "firebase.json" ]]; then
        cat > "firebase.json" << 'EOF'
{
  "hosting": {
    "public": "build/web",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ],
    "rewrites": [
      {
        "source": "**",
        "destination": "/index.html"
      }
    ]
  },
  "functions": {
    "predeploy": [
      "npm --prefix \"$RESOURCE_DIR\" run lint"
    ]
  }
}
EOF
        echo -e "${GREEN}✅ Created firebase.json${NC}"
    fi
    
    echo ""
}

# Generate GitHub secrets documentation
generate_secrets_documentation() {
    print_step "Generating GitHub secrets documentation"
    
    local secrets_file="GITHUB_SECRETS.md"
    
    cat > "$secrets_file" << 'EOF'
# GitHub Secrets Configuration

This document lists all the secrets required for the CI/CD pipeline.

## Required Secrets

### Android Deployment
- `ANDROID_KEYSTORE_BASE64` - Base64 encoded Android keystore file
- `ANDROID_KEYSTORE_PASSWORD` - Password for the Android keystore
- `ANDROID_KEY_ALIAS` - Alias for the Android signing key
- `ANDROID_KEY_PASSWORD` - Password for the Android signing key
- `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` - Google Play Console service account JSON

### iOS Deployment
- `IOS_CERTIFICATE_BASE64` - Base64 encoded iOS distribution certificate (.p12)
- `IOS_CERTIFICATE_PASSWORD` - Password for the iOS certificate
- `IOS_PROVISIONING_PROFILE_BASE64` - Base64 encoded provisioning profile
- `IOS_TEAM_ID` - Apple Developer Team ID
- `APPSTORE_ISSUER_ID` - App Store Connect API issuer ID
- `APPSTORE_API_KEY_ID` - App Store Connect API key ID
- `APPSTORE_API_PRIVATE_KEY` - App Store Connect API private key

### Firebase
- `FIREBASE_APP_ID` - Firebase App ID for production
- `FIREBASE_APP_ID_STAGING` - Firebase App ID for staging
- `FIREBASE_TOKEN` - Firebase CLI token

### Notifications
- `SLACK_WEBHOOK_URL` - Slack webhook URL for notifications

## How to Generate Base64 Encoded Secrets

### For files (certificates, keystores, etc.):
```bash
base64 -w 0 path/to/file.ext
```

### For macOS:
```bash
base64 path/to/file.ext
```

## Setting Up Secrets in GitHub

1. Go to your repository on GitHub
2. Click on "Settings" tab
3. Click on "Secrets and variables" → "Actions"
4. Click "New repository secret"
5. Add the secret name and value
6. Click "Add secret"

## Verification

After setting up all secrets, the CI/CD pipeline should work correctly. You can verify by:
1. Creating a pull request
2. Checking if all workflow jobs pass
3. Reviewing the build artifacts

## Security Notes

- Never commit secrets to the repository
- Regularly rotate certificates and API keys
- Use least privilege principle for service accounts
- Monitor secret usage and access logs

EOF
    
    echo -e "${GREEN}✅ Generated GitHub secrets documentation: $secrets_file${NC}"
    echo ""
}

# Setup project configuration
setup_project_config() {
    print_step "Setting up project configuration"
    
    # Create scripts directory if it doesn't exist
    mkdir -p scripts
    
    # Create build configuration file
    cat > "build.yaml" << 'EOF'
targets:
  $default:
    builders:
      json_annotation:
        enabled: true
        options:
          any_map: true
          checked: true
          create_factory: true
          create_to_json: true
          disallow_unrecognized_keys: false
          explicit_to_json: true
          generic_argument_factories: true
          include_if_null: true
EOF
    
    # Add CI/CD specific analysis options
    if [[ -f "analysis_options.yaml" ]]; then
        echo -e "${GREEN}✅ analysis_options.yaml already exists${NC}"
    else
        cat > "analysis_options.yaml" << 'EOF'
include: package:flutter_lints/flutter.yaml

analyzer:
  plugins:
    - dart_code_metrics
  exclude:
    - "**/*.g.dart"
    - "**/*.freezed.dart"
    - "**/*.config.dart"
    - "build/**"
    - "lib/generated_plugin_registrant.dart"
  strong-mode:
    implicit-casts: false
    implicit-dynamic: false
  errors:
    invalid_assignment: warning
    missing_enum_constant_in_switch: error
    missing_required_param: error
    missing_return: error

linter:
  rules:
    - always_declare_return_types
    - avoid_print
    - avoid_slow_async_io
    - cancel_subscriptions
    - close_sinks
    - comment_references
    - control_flow_in_finally
    - empty_statements
    - hash_and_equals
    - invariant_booleans
    - iterable_contains_unrelated_type
    - list_remove_unrelated_type
    - literal_only_boolean_expressions
    - no_adjacent_strings_in_list
    - no_duplicate_case_values
    - prefer_void_to_null
    - test_types_in_equals
    - throw_in_finally
    - unnecessary_statements
    - unrelated_type_equality_checks
    - valid_regexps

dart_code_metrics:
  anti-patterns:
    - long-method
    - long-parameter-list
  metrics:
    cyclomatic-complexity: 20
    maximum-nesting-level: 5
    number-of-parameters: 4
    source-lines-of-code: 50
  metrics-exclude:
    - test/**
  rules:
    - avoid-dynamic
    - avoid-returning-widgets
    - avoid-unnecessary-setstate
    - avoid-wrapping-in-padding
    - binary-expression-operand-order
    - double-literal-format
    - newline-before-return
    - no-boolean-literal-compare
    - no-empty-block
    - prefer-conditional-expressions
    - prefer-single-widget-per-file
EOF
        echo -e "${GREEN}✅ Created analysis_options.yaml${NC}"
    fi
    
    echo ""
}

# Generate final setup report
generate_setup_report() {
    print_step "Generating setup report"
    
    local report_file="CI_CD_SETUP_REPORT.md"
    
    cat > "$report_file" << EOF
# CI/CD Setup Report

Generated on: $(date)

## Setup Status

### ✅ Completed
- Environment files created
- Android signing configuration
- Project configuration files
- Build and analysis configurations
- GitHub secrets documentation
- Firebase configuration template

### ⚠️ Manual Configuration Required

#### Android Signing
1. Replace the debug keystore with your production keystore
2. Update key.properties with production values
3. Add ANDROID_* secrets to GitHub

#### iOS Signing (macOS only)
1. Configure signing in Xcode
2. Export certificates and provisioning profiles
3. Add IOS_* secrets to GitHub

#### Firebase
1. Set up Firebase projects for each environment
2. Download and add google-services.json and GoogleService-Info.plist
3. Add FIREBASE_* secrets to GitHub

#### GitHub Secrets
1. Configure all required secrets listed in GITHUB_SECRETS.md
2. Test the CI/CD pipeline with a pull request

## Next Steps

1. Review and customize environment configurations
2. Set up production signing certificates
3. Configure Firebase projects
4. Add all required GitHub secrets
5. Test the CI/CD pipeline
6. Monitor and optimize build performance

## Files Created

- lib/env/env.dev.dart
- lib/env/env.staging.dart
- lib/env/env.prod.dart
- lib/env/env.dart
- android/key.properties
- ios/ExportOptions.plist (if on macOS)
- firebase.json
- build.yaml
- analysis_options.yaml
- GITHUB_SECRETS.md
- CI_CD_SETUP_REPORT.md

## Documentation

- CI-CD-README.md - Comprehensive CI/CD documentation
- GITHUB_SECRETS.md - GitHub secrets configuration guide

EOF
    
    echo -e "${GREEN}✅ Generated setup report: $report_file${NC}"
    echo ""
}

# Main setup function
main() {
    echo -e "${BLUE}🚀 Starting CI/CD setup process...${NC}"
    echo ""
    
    # Change to script directory
    cd "$(dirname "$0")"
    
    # Change to Flutter project root
    cd ..
    
    check_prerequisites
    setup_environment_files
    setup_android_signing
    setup_ios_signing
    setup_firebase_config
    setup_project_config
    generate_secrets_documentation
    generate_setup_report
    
    echo -e "${GREEN}🎉 CI/CD setup completed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}📋 Next steps:${NC}"
    echo "1. Review the generated files and configurations"
    echo "2. Set up production signing certificates"
    echo "3. Configure Firebase projects"
    echo "4. Add required GitHub secrets"
    echo "5. Test the CI/CD pipeline"
    echo ""
    echo -e "${BLUE}📖 Documentation:${NC}"
    echo "- CI-CD-README.md - Comprehensive CI/CD guide"
    echo "- GITHUB_SECRETS.md - GitHub secrets configuration"
    echo "- CI_CD_SETUP_REPORT.md - Setup completion report"
    echo ""
}

# Run main function
main "$@"