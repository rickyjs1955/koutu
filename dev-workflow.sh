#!/bin/bash
# dev-workflow.sh - Your daily development workflow

echo "🚀 Koutu Development Environment"
echo "==============================="

# Function to start development environment
start_dev() {
    echo "🐳 Starting development containers..."
    docker-compose up -d
    
    echo "⏳ Waiting for services..."
    sleep 10
    
    echo "🔍 Checking service health..."
    
    # Check Firebase emulators
    if curl -s http://localhost:9099 > /dev/null; then
        echo "✅ Firebase Auth: Ready"
    else
        echo "❌ Firebase Auth: Not ready"
    fi
    
    if curl -s http://localhost:9100 > /dev/null; then
        echo "✅ Firebase Firestore: Ready"
    else
        echo "❌ Firebase Firestore: Not ready"
    fi
    
    if curl -s http://localhost:9199 > /dev/null; then
        echo "✅ Firebase Storage: Ready"
    else
        echo "❌ Firebase Storage: Not ready"
    fi
    
    # Check PostgreSQL
    if docker exec koutu-postgres pg_isready -U postgres > /dev/null 2>&1; then
        echo "✅ PostgreSQL (dev): Ready"
    else
        echo "❌ PostgreSQL (dev): Not ready"
    fi
    
    if docker exec koutu-postgres-test pg_isready -U postgres > /dev/null 2>&1; then
        echo "✅ PostgreSQL (test): Ready"
    else
        echo "❌ PostgreSQL (test): Not ready"
    fi
    
    echo ""
    echo "🌐 Available Services:"
    echo "• Firebase UI:    http://localhost:4000"
    echo "• Auth Emulator:  localhost:9099"
    echo "• Firestore:      localhost:9100"
    echo "• Storage:        localhost:9199"
    echo "• PostgreSQL:     localhost:5432"
    echo "• PostgreSQL Test: localhost:5433"
}

# Function to run tests
run_tests() {
    echo "🧪 Running Firebase tests..."
    cd backend
    
    # Set environment variables
    export NODE_ENV=test
    export FIRESTORE_EMULATOR_HOST=localhost:9100
    export FIREBASE_AUTH_EMULATOR_HOST=localhost:9099
    export FIREBASE_STORAGE_EMULATOR_HOST=localhost:9199
    export GCLOUD_PROJECT=demo-test-project
    
    # Clear emulator data
    curl -s -X DELETE "http://localhost:9099/emulator/v1/projects/demo-test-project/accounts" > /dev/null
    
    # Run Firebase tests
    npx jest firebase-quick-test.test.ts --verbose
    
    cd ..
}

# Function to clear emulator data
clear_data() {
    echo "🧹 Clearing Firebase emulator data..."
    curl -s -X DELETE "http://localhost:9099/emulator/v1/projects/demo-test-project/accounts" > /dev/null
    curl -s -X DELETE "http://localhost:9100/emulator/v1/projects/demo-test-project/databases/(default)/documents" > /dev/null
    echo "✅ Emulator data cleared"
}

# Function to show logs
show_logs() {
    echo "📋 Recent Firebase emulator logs:"
    docker logs koutu-firebase-emulator --tail 20
}

# Function to stop everything
stop_dev() {
    echo "🛑 Stopping development environment..."
    docker-compose down
    echo "✅ All services stopped"
}

# Function to restart everything
restart_dev() {
    echo "🔄 Restarting development environment..."
    stop_dev
    sleep 3
    start_dev
}

# Function to open Firebase UI
open_ui() {
    echo "🌐 Opening Firebase UI..."
    if command -v start > /dev/null; then
        start http://localhost:4000  # Windows
    elif command -v open > /dev/null; then
        open http://localhost:4000   # macOS
    else
        echo "Open http://localhost:4000 in your browser"
    fi
}

# Main menu
case "${1:-help}" in
    "start"|"up")
        start_dev
        ;;
    "test")
        run_tests
        ;;
    "clear")
        clear_data
        ;;
    "logs")
        show_logs
        ;;
    "stop"|"down")
        stop_dev
        ;;
    "restart")
        restart_dev
        ;;
    "ui")
        open_ui
        ;;
    "status")
        docker-compose ps
        ;;
    "help"|*)
        echo "Usage: $0 {start|test|clear|logs|stop|restart|ui|status}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all development services"
        echo "  test     - Run Firebase integration tests"
        echo "  clear    - Clear Firebase emulator data"
        echo "  logs     - Show Firebase emulator logs"
        echo "  stop     - Stop all services"
        echo "  restart  - Restart all services"
        echo "  ui       - Open Firebase emulator UI"
        echo "  status   - Show container status"
        echo ""
        echo "🎯 Quick start: $0 start"
        ;;
esac