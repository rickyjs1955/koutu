# docker/firebase-emulator/Dockerfile
FROM node:20-alpine

# Install dependencies
RUN apk add --no-cache openjdk17-jre curl bash

# Set working directory
WORKDIR /firebase

# Install Firebase CLI
RUN npm install -g firebase-tools@latest

# Copy startup script first
COPY start-emulators.sh /start-emulators.sh
RUN chmod +x /start-emulators.sh

# Copy configuration files
COPY firebase.json .
COPY .firebaserc .
COPY firestore.rules .
COPY storage.rules .
COPY firestore.indexes.json .

# Create data directory
RUN mkdir -p /firebase/data

# Expose ports
EXPOSE 4001 9099 9100 9199

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:9099 || exit 1

CMD ["/start-emulators.sh"]