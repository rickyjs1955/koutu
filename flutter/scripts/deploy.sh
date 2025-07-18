#!/bin/bash

# Flutter Deployment Script
# Usage: ./deploy.sh [environment] [platform]
# Example: ./deploy.sh staging android

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=${1:-dev}
PLATFORM=${2:-android}
BUILD_MODE="release"
FLUTTER_VERSION="3.22.0"

echo -e "${BLUE}🚀 Flutter Deployment Script${NC}"
echo -e "${BLUE}==============================${NC}"
echo -e "Environment: ${GREEN}$ENVIRONMENT${NC}"
echo -e "Platform: ${GREEN}$PLATFORM${NC}"
echo -e "Build Mode: ${GREEN}$BUILD_MODE${NC}"
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

# Validate inputs
validate_inputs() {
    print_step "Validating inputs"
    
    if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|production)$ ]]; then
        handle_error "Invalid environment: $ENVIRONMENT. Must be one of: dev, staging, production"
    fi
    
    if [[ ! "$PLATFORM" =~ ^(android|ios|both)$ ]]; then
        handle_error "Invalid platform: $PLATFORM. Must be one of: android, ios, both"
    fi
    
    echo -e "${GREEN}✅ Inputs validated successfully${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites"
    
    if ! command_exists flutter; then
        handle_error "Flutter is not installed or not in PATH"
    fi
    
    if ! command_exists git; then
        handle_error "Git is not installed or not in PATH"
    fi
    
    # Check Flutter version
    CURRENT_FLUTTER_VERSION=$(flutter --version | grep -o "Flutter [0-9]\+\.[0-9]\+\.[0-9]\+" | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+")
    echo "Current Flutter version: $CURRENT_FLUTTER_VERSION"
    echo "Expected Flutter version: $FLUTTER_VERSION"
    
    if [[ "$PLATFORM" == "android" || "$PLATFORM" == "both" ]]; then
        if ! command_exists java; then
            handle_error "Java is not installed or not in PATH (required for Android builds)"
        fi
    fi
    
    if [[ "$PLATFORM" == "ios" || "$PLATFORM" == "both" ]]; then
        if [[ "$OSTYPE" != "darwin"* ]]; then
            handle_error "iOS builds are only supported on macOS"
        fi
        
        if ! command_exists xcodebuild; then
            handle_error "Xcode is not installed or not in PATH (required for iOS builds)"
        fi
    fi
    
    echo -e "${GREEN}✅ Prerequisites check passed${NC}"
    echo ""
}

# Setup environment
setup_environment() {
    print_step "Setting up environment"
    
    # Set environment configuration
    case "$ENVIRONMENT" in
        "production")
            cp lib/env/env.prod.dart lib/env/env.dart
            echo "Using production environment configuration"
            ;;
        "staging")
            cp lib/env/env.staging.dart lib/env/env.dart
            echo "Using staging environment configuration"
            ;;
        *)
            cp lib/env/env.dev.dart lib/env/env.dart
            echo "Using development environment configuration"
            ;;
    esac
    
    echo -e "${GREEN}✅ Environment setup completed${NC}"
    echo ""
}

# Install dependencies
install_dependencies() {
    print_step "Installing dependencies"
    
    echo "Running flutter pub get..."
    flutter pub get
    
    echo "Running flutter pub upgrade..."
    flutter pub upgrade
    
    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
    echo ""
}

# Run pre-deployment checks
run_pre_deployment_checks() {
    print_step "Running pre-deployment checks"
    
    echo "Running Flutter doctor..."
    flutter doctor
    
    echo "Running code analysis..."
    flutter analyze
    
    echo "Running tests..."
    flutter test --coverage
    
    echo "Checking formatting..."
    dart format --set-exit-if-changed .
    
    echo -e "${GREEN}✅ Pre-deployment checks passed${NC}"
    echo ""
}

# Build Android
build_android() {
    print_step "Building Android application"
    
    # Set flavor based on environment
    FLAVOR=""
    case "$ENVIRONMENT" in
        "production")
            FLAVOR="--flavor prod"
            ;;
        "staging")
            FLAVOR="--flavor staging"
            ;;
        *)
            FLAVOR="--flavor dev"
            ;;
    esac
    
    echo "Building Android APK..."
    flutter build apk --$BUILD_MODE $FLAVOR
    
    if [[ "$BUILD_MODE" == "release" ]]; then
        echo "Building Android App Bundle..."
        flutter build appbundle --$BUILD_MODE $FLAVOR
    fi
    
    echo -e "${GREEN}✅ Android build completed${NC}"
    echo ""
}

# Build iOS
build_ios() {
    print_step "Building iOS application"
    
    # Set flavor based on environment
    FLAVOR=""
    case "$ENVIRONMENT" in
        "production")
            FLAVOR="--flavor prod"
            ;;
        "staging")
            FLAVOR="--flavor staging"
            ;;
        *)
            FLAVOR="--flavor dev"
            ;;
    esac
    
    echo "Building iOS application..."
    if [[ "$BUILD_MODE" == "release" && "$ENVIRONMENT" != "dev" ]]; then
        flutter build ios --$BUILD_MODE $FLAVOR
    else
        flutter build ios --$BUILD_MODE --no-codesign $FLAVOR
    fi
    
    if [[ "$BUILD_MODE" == "release" && "$ENVIRONMENT" != "dev" ]]; then
        echo "Creating iOS archive..."
        cd ios
        xcodebuild -workspace Runner.xcworkspace \
            -scheme Runner \
            -configuration Release \
            -destination generic/platform=iOS \
            -archivePath build/Runner.xcarchive \
            archive
        cd ..
    fi
    
    echo -e "${GREEN}✅ iOS build completed${NC}"
    echo ""
}

# Deploy to Firebase App Distribution
deploy_to_firebase() {
    print_step "Deploying to Firebase App Distribution"
    
    if ! command_exists firebase; then
        echo -e "${YELLOW}⚠️  Firebase CLI not found. Installing...${NC}"
        npm install -g firebase-tools
    fi
    
    # Deploy Android APK
    if [[ "$PLATFORM" == "android" || "$PLATFORM" == "both" ]]; then
        echo "Deploying Android APK to Firebase App Distribution..."
        
        APK_PATH="build/app/outputs/flutter-apk/app-${BUILD_MODE}.apk"
        if [[ -f "$APK_PATH" ]]; then
            firebase appdistribution:distribute "$APK_PATH" \
                --app "$FIREBASE_APP_ID" \
                --groups "internal-testers" \
                --release-notes "Environment: $ENVIRONMENT, Build: $(date +%Y%m%d%H%M%S)"
        else
            handle_error "APK not found at $APK_PATH"
        fi
    fi
    
    echo -e "${GREEN}✅ Firebase deployment completed${NC}"
    echo ""
}

# Generate build report
generate_build_report() {
    print_step "Generating build report"
    
    REPORT_FILE="build_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$REPORT_FILE" << EOF
# Build Report

## Build Information
- **Environment:** $ENVIRONMENT
- **Platform:** $PLATFORM  
- **Build Mode:** $BUILD_MODE
- **Timestamp:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
- **Flutter Version:** $(flutter --version | head -1)
- **Git Commit:** $(git rev-parse HEAD)
- **Git Branch:** $(git rev-parse --abbrev-ref HEAD)

## Build Results
EOF

    if [[ "$PLATFORM" == "android" || "$PLATFORM" == "both" ]]; then
        echo "- **Android APK:** $(ls -la build/app/outputs/flutter-apk/app-*.apk 2>/dev/null || echo "Not found")" >> "$REPORT_FILE"
        
        if [[ "$BUILD_MODE" == "release" ]]; then
            echo "- **Android AAB:** $(ls -la build/app/outputs/bundle/*/app-*.aab 2>/dev/null || echo "Not found")" >> "$REPORT_FILE"
        fi
    fi
    
    if [[ "$PLATFORM" == "ios" || "$PLATFORM" == "both" ]]; then
        echo "- **iOS Build:** $(ls -la build/ios/iphoneos/Runner.app 2>/dev/null || echo "Not found")" >> "$REPORT_FILE"
        
        if [[ "$BUILD_MODE" == "release" && "$ENVIRONMENT" != "dev" ]]; then
            echo "- **iOS Archive:** $(ls -la ios/build/Runner.xcarchive 2>/dev/null || echo "Not found")" >> "$REPORT_FILE"
        fi
    fi
    
    cat >> "$REPORT_FILE" << EOF

## Environment Configuration
- **API Base URL:** $(grep -o "baseUrl.*" lib/env/env.dart | head -1 || echo "Not found")
- **Build Configuration:** $ENVIRONMENT

## Next Steps
- Review build artifacts
- Test on target devices
- Deploy to app stores (if applicable)

---
*Generated by deploy.sh on $(date)*
EOF
    
    echo "Build report generated: $REPORT_FILE"
    echo -e "${GREEN}✅ Build report generated successfully${NC}"
    echo ""
}

# Main deployment function
main() {
    echo -e "${BLUE}🚀 Starting Flutter deployment process...${NC}"
    echo ""
    
    # Change to script directory
    cd "$(dirname "$0")"
    
    # Change to Flutter project root
    cd ..
    
    validate_inputs
    check_prerequisites
    setup_environment
    install_dependencies
    run_pre_deployment_checks
    
    # Build based on platform
    if [[ "$PLATFORM" == "android" || "$PLATFORM" == "both" ]]; then
        build_android
    fi
    
    if [[ "$PLATFORM" == "ios" || "$PLATFORM" == "both" ]]; then
        build_ios
    fi
    
    # Deploy to Firebase (if environment variables are set)
    if [[ -n "$FIREBASE_APP_ID" ]]; then
        deploy_to_firebase
    else
        echo -e "${YELLOW}⚠️  FIREBASE_APP_ID not set. Skipping Firebase deployment.${NC}"
    fi
    
    generate_build_report
    
    echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
    echo ""
    echo "Build artifacts:"
    
    if [[ "$PLATFORM" == "android" || "$PLATFORM" == "both" ]]; then
        echo "- Android APK: build/app/outputs/flutter-apk/"
        if [[ "$BUILD_MODE" == "release" ]]; then
            echo "- Android AAB: build/app/outputs/bundle/"
        fi
    fi
    
    if [[ "$PLATFORM" == "ios" || "$PLATFORM" == "both" ]]; then
        echo "- iOS Build: build/ios/"
        if [[ "$BUILD_MODE" == "release" && "$ENVIRONMENT" != "dev" ]]; then
            echo "- iOS Archive: ios/build/Runner.xcarchive"
        fi
    fi
}

# Run main function
main "$@"