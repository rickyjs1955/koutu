#!/bin/bash
set -e

echo "🔥 Firebase Emulator Suite Starting..."
echo "📅 $(date)"
echo "🐳 Container: $(hostname)"

echo "☕ Java version:"
java -version

echo "📦 Node.js version:"
node --version
npm --version

echo "🔧 Firebase CLI version:"
firebase --version

echo "📁 Working directory:"
pwd
ls -la

echo "🗂️ Firebase config (firebase.json):"
if [ -f "firebase.json" ]; then
    cat firebase.json
    echo ""
    echo "✅ firebase.json found"
else
    echo "❌ firebase.json NOT found"
fi

echo "🔍 .firebaserc config:"
if [ -f ".firebaserc" ]; then
    cat .firebaserc
    echo ""
    echo "✅ .firebaserc found"
else
    echo "❌ .firebaserc NOT found"
fi

echo "📋 Rules files:"
if [ -f "firestore.rules" ]; then
    echo "✅ firestore.rules found"
    head -3 firestore.rules
else
    echo "❌ firestore.rules NOT found"
fi

if [ -f "storage.rules" ]; then
    echo "✅ storage.rules found"
    head -3 storage.rules
else
    echo "❌ storage.rules NOT found"
fi

if [ -f "firestore.indexes.json" ]; then
    echo "✅ firestore.indexes.json found"
else
    echo "❌ firestore.indexes.json NOT found"
fi

echo ""
echo "🚀 Starting Firebase Emulators..."
echo "💡 Note: Running in demo mode - no authentication required"
echo "Command: firebase emulators:start --only auth,firestore,storage"

# Start emulators directly - no authentication needed for demo project
firebase emulators:start --only auth,firestore,storage