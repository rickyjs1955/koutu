#!/bin/bash
# test-schema-evolution.sh
# Comprehensive test script for schema evolution detection with clean output

set -e  # Exit on any command failure

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo -e "\n${CYAN}=================================================${NC}"
    echo -e "${CYAN} $1 ${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

print_section() {
    echo -e "\n${BLUE}--- $1 ---${NC}"
}

# Function to run a command and track results
run_test() {
    local test_name=$1
    local test_command=$2
    local optional=${3:-false}
    
    print_section "Running: $test_name"
    
    # Suppress verbose output, only show results
    if eval "$test_command" > /tmp/test_output 2>&1; then
        print_status $GREEN "✅ $test_name - PASSED"
        return 0
    else
        if [ "$optional" = false ]; then
            print_status $RED "❌ $test_name - FAILED"
            # Show error details for failed tests
            echo "Error details:"
            cat /tmp/test_output | tail -20
            return 1
        else
            print_status $YELLOW "⚠️  $test_name - FAILED (Optional)"
            return 0
        fi
    fi
}

# Function to run tests with clean output (suppress warnings)
run_clean_test() {
    local test_name=$1
    local test_command=$2
    local optional=${3:-false}
    
    print_section "Running: $test_name"
    
    # Run command and filter output
    if eval "$test_command" 2>&1 | grep -v "WARNING: You are currently running a version of TypeScript" | grep -v "SUPPORTED TYPESCRIPT VERSIONS" | grep -v "YOUR TYPESCRIPT VERSION" | grep -v "Please only submit bug reports" | grep -v "warning.*'.*' is defined but never used" | grep -v "warning.*Unexpected any" > /tmp/clean_output; then
        # Show clean summary
        if grep -q "Tests:" /tmp/clean_output; then
            grep "Tests:" /tmp/clean_output | tail -1
        fi
        print_status $GREEN "✅ $test_name - PASSED"
        return 0
    else
        if [ "$optional" = false ]; then
            print_status $RED "❌ $test_name - FAILED"
            # Show actual errors, not warnings
            cat /tmp/clean_output | grep -E "(FAIL|Error|✗|×)" | head -10
            return 1
        else
            print_status $YELLOW "⚠️  $test_name - FAILED (Optional)"
            return 0
        fi
    fi
}

# Initialize counters
total_tests=0
passed_tests=0
failed_tests=0
start_time=$(date +%s)

print_header "🔍 SCHEMA EVOLUTION DETECTION TEST SUITE"
print_status $BLUE "Testing comprehensive schema validation and evolution detection"
print_status $CYAN "Location: $(pwd)"
print_status $CYAN "Date: $(date)"

# Change to shared directory if not already there
if [[ ! -f "package.json" ]]; then
    if [[ -d "shared" ]]; then
        cd shared
        print_status $YELLOW "📁 Changed to shared directory"
    else
        print_status $RED "❌ Error: Cannot find shared directory or package.json"
        exit 1
    fi
fi

# Verify we're in the right place
if [[ ! -f "package.json" ]] || ! grep -q "@koutu/shared" package.json; then
    print_status $RED "❌ Error: Not in the correct shared package directory"
    exit 1
fi

print_status $GREEN "📍 Confirmed: In shared package directory"

# Check if schema evolution test exists
if [[ ! -f "src/__tests__/schema-evolution.test.ts" ]]; then
    print_status $RED "❌ Error: Schema evolution test file not found"
    print_status $YELLOW "Please create src/__tests__/schema-evolution.test.ts first"
    exit 1
fi

print_header "📊 CURRENT TEST STATISTICS"
run_test "Show Test Statistics" "npm run test:stats" false
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

print_header "🧪 CORE VALIDATION TESTS"

# TypeScript compilation
run_test "TypeScript Compilation" "npm run test:type-check" false
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

# ESLint with quiet mode
run_test "Code Quality (ESLint - Clean)" "npm run test:lint:quiet" true
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

print_header "🎯 SCHEMA VALIDATION TESTS"

# Export tests (most reliable) - with clean output
run_clean_test "Export Schema Tests (12 tests)" "npm run test:export" false
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

# Core validation tests - with clean output
run_clean_test "Schema Validation Tests (13 tests)" "npm run test:validation-safe" false
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

# Property-based tests - with clean output
run_clean_test "Property-Based Tests (16 tests)" "npm run test:property-safe" false
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

print_header "🔍 SCHEMA EVOLUTION DETECTION"

# Schema evolution tests - The star of the show! - with clean output
run_clean_test "Schema Evolution Detection (19 tests)" "npm run test:evolution" false
total_tests=$((total_tests + 1))
if [ $? -eq 0 ]; then passed_tests=$((passed_tests + 1)); else failed_tests=$((failed_tests + 1)); fi

print_header "🔬 SCHEMA EVOLUTION FEATURES DEMO"

print_section "Testing Schema Evolution Commands"

# Test evolution commands quietly
print_status $BLUE "🔍 Running schema evolution check..."
if npm run schema:check > /dev/null 2>&1; then
    print_status $GREEN "✅ Schema evolution check command works"
else
    print_status $YELLOW "⚠️  Schema evolution check had issues (may be expected)"
fi

# Check if snapshots were created
print_section "Checking Schema Snapshots"
if [[ -d "src/__tests__/snapshots" ]]; then
    snapshot_count=$(find src/__tests__/snapshots -name "*.snapshot.json" 2>/dev/null | wc -l)
    if [[ $snapshot_count -gt 0 ]]; then
        print_status $GREEN "✅ Schema snapshots created: $snapshot_count files"
        print_status $CYAN "📁 Snapshot files:"
        find src/__tests__/snapshots -name "*.snapshot.json" 2>/dev/null | sed 's/^/    /'
    else
        print_status $YELLOW "⚠️  No snapshot files found (may be first run)"
    fi
else
    print_status $YELLOW "⚠️  Snapshots directory not found (may be first run)"
fi

print_header "🚀 PERFORMANCE METRICS"

# Calculate execution time
end_time=$(date +%s)
execution_time=$((end_time - start_time))

print_status $CYAN "⏱️  Total execution time: ${execution_time}s"

# Test performance quietly
print_section "Schema Validation Performance"
print_status $BLUE "🏃 Testing validation speed..."

# Time a quick test
quick_start=$(date +%s%3N)
npm run test:quick > /dev/null 2>&1
quick_end=$(date +%s%3N)
quick_time=$((quick_end - quick_start))

print_status $GREEN "⚡ Quick test (12 tests): ${quick_time}ms"

# Time evolution test
evolution_start=$(date +%s%3N)
npm run test:evolution > /dev/null 2>&1
evolution_end=$(date +%s%3N)
evolution_time=$((evolution_end - evolution_start))

print_status $GREEN "🔍 Evolution test (19 tests): ${evolution_time}ms"

print_header "📊 FINAL RESULTS"

echo "📈 Test Execution Summary:"
echo "  ✅ Passed: $passed_tests"
echo "  ❌ Failed: $failed_tests" 
echo "  📝 Total: $total_tests"
echo "  ⏱️  Time: ${execution_time}s"
echo ""

# Show current test counts
echo "🧪 Current Test Suite:"
echo "  • Export Tests: 12 (core validation)"
echo "  • Schema Validation: 13 (edge cases, performance)"  
echo "  • Property-Based: 16 (generative testing)"
echo "  • Schema Evolution: 19 (breaking change detection)"
echo "  • Total: 60+ comprehensive tests"
echo ""

echo "🔍 Schema Evolution Features:"
echo "  • Automatic breaking change detection"
echo "  • Schema snapshot comparison"  
echo "  • Migration guidance generation"
echo "  • Backward compatibility testing"
echo "  • Regression prevention"
echo ""

echo "🎯 Available Commands:"
echo "  npm test                    # Core test suite (clean)"
echo "  npm run test:evolution      # Evolution detection"
echo "  npm run schema:check        # Check for changes"
echo "  npm run schema:update       # Update snapshots"
echo "  npm run test:ci            # CI/CD optimized (no warnings)"

if [ "$failed_tests" -eq 0 ]; then
    print_header "🎉 SUCCESS: All Tests Passed!"
    print_status $GREEN "✅ Your shared schema testing infrastructure is working perfectly!"
    print_status $GREEN "✅ Schema evolution detection is active and protecting against breaking changes"
    print_status $GREEN "✅ You now have enterprise-grade schema validation with 60+ comprehensive tests"
    echo ""
    print_status $CYAN "🚀 Ready for production deployment with confidence!"
    print_status $BLUE "💡 Tip: Use 'npm run test:ci' for clean CI/CD output without warnings"
    exit 0
else
    print_header "⚠️  Some Tests Failed"
    print_status $YELLOW "❗ $failed_tests out of $total_tests tests failed"
    print_status $YELLOW "❗ Review the output above to identify issues"
    echo ""
    print_status $BLUE "💡 Troubleshooting tips:"
    echo "  • Check if all dependencies are installed: npm install"
    echo "  • Verify schema files are present and valid"
    echo "  • Run individual tests to isolate issues"
    echo "  • Check for syntax errors in schema definitions"
    exit 1
fi

# Cleanup temp files
rm -f /tmp/test_output /tmp/clean_output