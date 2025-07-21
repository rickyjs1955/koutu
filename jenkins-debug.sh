#!/bin/bash

# Jenkins Debug Script
echo "=== Jenkins Debug Information ==="
echo "Date: $(date)"
echo

echo "1. Checking Node.js installations:"
which node && node --version || echo "Node not found in PATH"
echo

echo "2. Checking npm:"
which npm && npm --version || echo "NPM not found in PATH"
echo

echo "3. Checking Git:"
which git && git --version || echo "Git not found"
echo

echo "4. Checking Java:"
java -version 2>&1 | head -3
echo

echo "5. Checking Jenkins workspace:"
ls -la /var/lib/jenkins/workspace/ 2>/dev/null || echo "Jenkins workspace not accessible"
echo

echo "6. Checking Koutu project:"
ls -la /home/monmonmic/koutu/ | head -10
echo

echo "7. Checking Git status in Koutu:"
cd /home/monmonmic/koutu && git status --short
echo

echo "8. Environment variables:"
env | grep -E "JAVA|NODE|NPM|PATH" | sort