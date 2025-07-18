# Flutter CI/CD Pipeline

This document describes the Continuous Integration and Continuous Deployment (CI/CD) pipeline for the Koutu Flutter application.

## Overview

The CI/CD pipeline consists of multiple workflows that handle different aspects of the development and deployment process:

1. **Flutter CI/CD Pipeline** - Main build and deployment workflow
2. **Code Quality Checks** - Comprehensive code analysis and quality metrics
3. **App Store Deployment** - Automated deployment to Google Play Store and Apple App Store
4. **Environment-Specific Builds** - Builds for different environments (dev, staging, production)

## Workflows

### 1. Flutter CI/CD Pipeline (`flutter-ci-cd.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual workflow dispatch

**Jobs:**
- **analyze** - Code analysis and formatting checks
- **test** - Unit, widget, and integration tests
- **build-android** - Build Android APK and AAB
- **build-ios** - Build iOS app and archive
- **security-scan** - Security vulnerability scanning
- **deploy-staging** - Deploy to staging environment
- **deploy-production** - Deploy to production environment
- **notify** - Send notifications to team

### 2. Code Quality Checks (`code-quality.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

**Jobs:**
- **dart-code-metrics** - Code complexity and maintainability metrics
- **dependency-analysis** - Dependency management and security analysis
- **test-coverage** - Test coverage analysis with threshold checking
- **performance-analysis** - App size and performance analysis
- **security-audit** - Security vulnerability scanning
- **generate-quality-report** - Consolidated quality report generation

### 3. App Store Deployment (`app-store-deployment.yml`)

**Triggers:**
- Manual workflow dispatch with parameters

**Jobs:**
- **prepare-release** - Version bumping and release preparation
- **deploy-android** - Deploy to Google Play Store
- **deploy-ios** - Deploy to Apple App Store
- **create-github-release** - Create GitHub release with artifacts
- **notify-team** - Send deployment notifications

### 4. Environment-Specific Builds (`environment-builds.yml`)

**Triggers:**
- Push to any branch
- Pull requests
- Scheduled nightly builds

**Jobs:**
- **determine-environment** - Determine target environment based on branch
- **build-android** - Build Android for all environments
- **build-ios** - Build iOS for all environments
- **test-builds** - Validate build artifacts
- **deploy-to-firebase** - Deploy to Firebase App Distribution
- **nightly-build-report** - Generate and send nightly build reports

## Environment Configuration

### Branch-Based Environment Mapping

- `main` → Production
- `develop` → Staging
- `feature/*` → Development (no deployment)
- `release/*` → Release Candidate (staging deployment)

### Environment Files

Environment-specific configurations are stored in:
- `lib/env/env.prod.dart` - Production environment
- `lib/env/env.staging.dart` - Staging environment
- `lib/env/env.dev.dart` - Development environment

## Required Secrets

### GitHub Secrets

Configure the following secrets in your GitHub repository:

#### Android Deployment
- `ANDROID_KEYSTORE_BASE64` - Base64 encoded Android keystore
- `ANDROID_KEYSTORE_PASSWORD` - Keystore password
- `ANDROID_KEY_ALIAS` - Key alias
- `ANDROID_KEY_PASSWORD` - Key password
- `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` - Google Play service account JSON

#### iOS Deployment
- `IOS_CERTIFICATE_BASE64` - Base64 encoded iOS distribution certificate
- `IOS_CERTIFICATE_PASSWORD` - Certificate password
- `IOS_PROVISIONING_PROFILE_BASE64` - Base64 encoded provisioning profile
- `IOS_TEAM_ID` - Apple Developer Team ID
- `APPSTORE_ISSUER_ID` - App Store Connect API issuer ID
- `APPSTORE_API_KEY_ID` - App Store Connect API key ID
- `APPSTORE_API_PRIVATE_KEY` - App Store Connect API private key

#### Firebase
- `FIREBASE_APP_ID` - Firebase App ID
- `FIREBASE_APP_ID_STAGING` - Firebase App ID for staging
- `FIREBASE_TOKEN` - Firebase CLI token

#### Notifications
- `SLACK_WEBHOOK_URL` - Slack webhook URL for notifications

## Local Development

### Deployment Script

Use the provided deployment script for local builds:

```bash
# Build for development
./scripts/deploy.sh dev android

# Build for staging
./scripts/deploy.sh staging android

# Build for production
./scripts/deploy.sh production both
```

### Script Options

- **Environment**: `dev`, `staging`, `production`
- **Platform**: `android`, `ios`, `both`

## Build Artifacts

### Android
- **APK**: `build/app/outputs/flutter-apk/app-*.apk`
- **AAB**: `build/app/outputs/bundle/*/app-*.aab`

### iOS
- **App**: `build/ios/iphoneos/Runner.app`
- **Archive**: `ios/build/Runner.xcarchive`
- **IPA**: `ios/build/Runner.ipa`

## Quality Gates

### Code Quality Standards

- **Test Coverage**: Minimum 80% line coverage
- **Code Analysis**: No analysis errors or warnings
- **Security**: No high-severity vulnerabilities
- **Performance**: APK size under 100MB

### Deployment Criteria

- All tests must pass
- Code analysis must pass
- Security scan must pass
- Build artifacts must be generated successfully

## Monitoring and Notifications

### Slack Notifications

The pipeline sends notifications to Slack channels:
- `#mobile-deployments` - Deployment status
- Build success/failure notifications
- Nightly build reports

### GitHub Actions

- Build status badges
- PR comments with quality metrics
- Artifact uploads for all builds
- Release notes generation

## Troubleshooting

### Common Issues

1. **Build Failures**
   - Check Flutter version compatibility
   - Verify all dependencies are correctly installed
   - Ensure environment configurations are correct

2. **Signing Issues**
   - Verify all certificates and profiles are correctly configured
   - Check that secrets are properly base64 encoded
   - Ensure provisioning profiles match the app bundle ID

3. **Deployment Failures**
   - Check API credentials and permissions
   - Verify app metadata and compliance requirements
   - Ensure proper versioning and build numbers

### Debug Information

Each workflow generates detailed logs and artifacts:
- Build logs available in GitHub Actions
- Test reports and coverage data
- Quality analysis reports
- Build artifacts for download

## Security Considerations

- All secrets are stored securely in GitHub Secrets
- Build artifacts are scanned for vulnerabilities
- Dependency security audits are performed
- Code is analyzed for potential security issues

## Performance Optimization

- Caching is used for dependencies and build artifacts
- Parallel builds for different platforms
- Incremental builds when possible
- Optimized Docker images for CI/CD runners

## Maintenance

### Regular Tasks

1. **Monthly**
   - Review and update Flutter version
   - Update dependencies and security patches
   - Review quality metrics and adjust thresholds

2. **Quarterly**
   - Review and update workflow configurations
   - Evaluate new tools and integrations
   - Performance optimization of CI/CD pipeline

3. **Annually**
   - Certificate and provisioning profile renewal
   - Review and update security practices
   - Evaluate infrastructure and tooling upgrades

## Support

For issues with the CI/CD pipeline:
1. Check the GitHub Actions logs
2. Review this documentation
3. Contact the DevOps team
4. Create an issue in the repository

---

*This documentation is maintained by the DevOps team and updated regularly.*