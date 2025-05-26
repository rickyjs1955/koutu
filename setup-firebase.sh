#!/bin/bash

# Create Firebase emulator directory structure
mkdir -p docker/firebase-emulator

# Navigate to Firebase emulator directory
cd docker/firebase-emulator

# Create .firebaserc file
cat > .firebaserc << 'EOF'
{
  "projects": {
    "default": "demo-test-project"
  }
}
EOF

# Create firebase.json file
cat > firebase.json << 'EOF'
{
  "emulators": {
    "auth": {
      "port": 9099,
      "host": "0.0.0.0"
    },
    "firestore": {
      "port": 9100,
      "host": "0.0.0.0"
    },
    "storage": {
      "port": 9199,
      "host": "0.0.0.0"
    },
    "ui": {
      "enabled": true,
      "port": 4000,
      "host": "0.0.0.0"
    }
  },
  "storage": {
    "rules": "storage.rules"
  },
  "firestore": {
    "rules": "firestore.rules"
  }
}
EOF

# Create firestore.rules file
cat > firestore.rules << 'EOF'
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true; // Allow all operations for testing
    }
  }
}
EOF

# Create storage.rules file
cat > storage.rules << 'EOF'
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true; // Allow all operations for testing
    }
  }
}
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM node:18-bullseye

# Install Java (required by Firebase emulators)
RUN apt-get update && apt-get install -y \
    openjdk-11-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Firebase CLI globally
RUN npm install -g firebase-tools

# Create app directory
WORKDIR /app

# Copy Firebase configuration files
COPY firebase.json .firebaserc firestore.rules storage.rules ./

# Expose ports for emulators
EXPOSE 4000 9099 9100 9199

# Start Firebase emulators
CMD ["firebase", "emulators:start", "--only", "auth,firestore,storage", "--project", "demo-test-project"]
EOF

echo "Firebase emulator setup complete!"
echo "Directory structure created with all necessary files."
echo ""
echo "Next steps:"
echo "1. Run: cd ../.."
echo "2. Run: docker-compose up firebase-emulator"
echo "3. Access Firebase UI at: http://localhost:4000"