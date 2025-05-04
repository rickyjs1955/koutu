#!/bin/bash

# This script sets up the development environment for the fashion data collector backend

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}======== Fashion Data Collector Backend Setup ========${NC}"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Node.js is not installed. Please install Node.js v16 or higher.${NC}"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d 'v' -f 2 | cut -d '.' -f 1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo -e "${RED}Node.js version $NODE_VERSION is too old. Please install Node.js v16 or higher.${NC}"
    exit 1
fi

echo -e "${GREEN}Node.js $(node -v) detected.${NC}"

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo -e "${YELLOW}PostgreSQL client does not seem to be installed or isn't in your PATH.${NC}"
    echo -e "${YELLOW}You will need PostgreSQL running for this application.${NC}"
    
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}PostgreSQL client detected.${NC}"
fi

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}No .env file found. Creating one from template...${NC}"
    
    # Create .env file
    cat > .env << 'EOF'
PORT=3000
NODE_ENV=development
DATABASE_URL=postgres://postgres:postgres@localhost:5432/fashion_data_collector
JWT_SECRET=dev_secret_change_this_in_production
MAX_FILE_SIZE=5242880
EOF
    
    echo -e "${GREEN}.env file created. Please update it with your database credentials.${NC}"
else
    echo -e "${GREEN}.env file found.${NC}"
fi

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
npm install

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
mkdir -p uploads exports

# Ask if user wants to set up database
echo
read -p "Do you want to set up the database (run migrations and seed data)? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Running database migrations...${NC}"
    npm run migrate
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Migrations completed successfully.${NC}"
        
        echo -e "${YELLOW}Seeding database with test data...${NC}"
        npm run seed
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Database seeded successfully.${NC}"
            echo -e "${GREEN}Test user created:${NC}"
            echo -e "${GREEN}  Email: test@example.com${NC}"
            echo -e "${GREEN}  Password: password123${NC}"
        else
            echo -e "${RED}Failed to seed database. Check the error above.${NC}"
        fi
    else
        echo -e "${RED}Database migrations failed. Check the error above.${NC}"
    fi
fi

# Build TypeScript
echo -e "${YELLOW}Building TypeScript...${NC}"
npm run build

# Ask if user wants to start the server
echo
read -p "Do you want to start the development server? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Starting development server...${NC}"
    npm run dev
else
    echo -e "${GREEN}Setup complete. Start the server with 'npm run dev' when you're ready.${NC}"
fi
