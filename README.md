# Koutu - Fashion Data Collection Platform

Koutu is a full-stack TypeScript application for collecting garment data through user-submitted images and manual background removal. The application serves as a data collection platform for a future AI-powered fashion application.

## Features

- **User Authentication**: Register and login to securely access your data
- **Image Upload**: Upload images of clothing items
- **Garment Extraction**: Tools to create garment cutouts with masks
- **Digital Wardrobe**: Organize extracted garments into collections
- **Data Export**: Export functionality for future migration to AI platform
- **Type Safety**: End-to-end type safety with shared Zod schemas

## Project Overview

![Koutu Architecture](docs/architecture-diagram.png)

## Tech Stack

### Backend
- Node.js + Express
- TypeScript
- PostgreSQL database
- JWT authentication
- Multer for file uploads
- Sharp for image processing

### Frontend
- React
- TypeScript
- Vite build system
- React Query for data fetching
- React Hook Form with Zod validation
- React Konva for image manipulation

### Shared
- Zod schemas for validation and type generation
- TypeScript project references

## Monorepo Structure

```
koutu/
├── package.json                  # Root package.json for monorepo setup
├── tsconfig.json                 # Base TypeScript config
│
├── shared/                       # Shared code between frontend and backend
│   ├── src/
│   │   └── schemas/              # Zod schemas directory
│   │       ├── user.ts
│   │       ├── image.ts
│   │       ├── garment.ts
│   │       ├── wardrobe.ts
│   │       └── export.ts
│
├── frontend/                     # Frontend React application
│   ├── src/
│   │   ├── components/           # React components
│   │   ├── hooks/                # Custom React hooks
│   │   ├── api/                  # API client code
│   │   ├── pages/                # Page components
│   │   └── ...
│
├── backend/                      # Backend Express application
│   ├── src/
│   │   ├── config/               # Configuration files
│   │   ├── controllers/          # Request handlers
│   │   ├── middlewares/          # Custom middleware functions
│   │   ├── models/               # Database models
│   │   ├── routes/               # API route definitions
│   │   ├── services/             # Business logic
│   │   ├── utils/                # Helper functions
│   │   └── app.ts                # Main application setup
│   ├── migrations/               # Database migrations
│   ├── scripts/                  # Utility scripts
│   ├── uploads/                  # Image storage
│   └── exports/                  # Data export files
│
└── docs/                         # Documentation
    ├── architecture-diagram.png  # Architecture diagram
    ├── api-docs.md               # API documentation
    └── koutu-api.postman_collection.json  # Postman collection
```

## Prerequisites

- Node.js (v16+)
- PostgreSQL (v13+)
- npm v7+ (for workspaces)

## Installation

1. Clone the repository
   ```
   git clone https://github.com/yourusername/koutu.git
   cd koutu
   ```

2. Install dependencies for all packages
   ```
   npm install
   ```

3. Build the shared package
   ```
   npm run build -w @koutu/shared
   ```

4. Configure environment variables
   - Copy `.env.example` to `.env` in the root directory
   - Update the database connection string and other settings

5. Set up the database
   ```
   npm run setup-db -w @koutu/backend
   ```
   This will:
   - Run migrations to create the necessary tables
   - Seed the database with test data

## Running the Application

### Development mode (both frontend and backend)
```
npm run dev
```

### Development mode (individual packages)
```
npm run dev -w @koutu/frontend
npm run dev -w @koutu/backend
```

### Production mode
```
npm run build
npm run start
```

## API Documentation

The API is organized around RESTful principles. All endpoints return JSON and require authentication via JWT bearer token (except for register/login).

### Authentication

- **POST** `/api/v1/auth/register`: Register a new user
- **POST** `/api/v1/auth/login`: Login and get JWT token
- **GET** `/api/v1/auth/me`: Get current user details

### Images

- **POST** `/api/v1/images/upload`: Upload a new image
- **GET** `/api/v1/images`: Get all user images
- **GET** `/api/v1/images/:id`: Get a specific image
- **DELETE** `/api/v1/images/:id`: Delete an image

### Garments

- **POST** `/api/v1/garments/create`: Create a new garment from mask data
- **GET** `/api/v1/garments`: Get all user garments
- **GET** `/api/v1/garments/:id`: Get a specific garment
- **PUT** `/api/v1/garments/:id/metadata`: Update garment metadata
- **DELETE** `/api/v1/garments/:id`: Delete a garment

### Wardrobes

- **POST** `/api/v1/wardrobes`: Create a new wardrobe
- **GET** `/api/v1/wardrobes`: Get all user wardrobes
- **GET** `/api/v1/wardrobes/:id`: Get a specific wardrobe with its garments
- **PUT** `/api/v1/wardrobes/:id`: Update wardrobe details
- **POST** `/api/v1/wardrobes/:id/items`: Add a garment to wardrobe
- **DELETE** `/api/v1/wardrobes/:id/items/:itemId`: Remove a garment from wardrobe
- **DELETE** `/api/v1/wardrobes/:id`: Delete a wardrobe

### Data Export

- **GET** `/api/v1/export/data`: Export user data as JSON
- **GET** `/api/v1/export/file`: Export user data to a file

For detailed request and response schemas, see the [API Documentation](docs/api-docs.md).

## Shared Schema Approach

Koutu uses Zod schemas to ensure type safety and validation across the full stack:

1. **Shared Package**: Defines Zod schemas for all data structures
2. **Backend Validation**: Uses schemas to validate all incoming requests
3. **Frontend Forms**: Uses the same schemas with React Hook Form
4. **TypeScript Types**: Automatically derives TypeScript types from schemas

This ensures consistent data structure between frontend and backend, eliminating bugs from mismatched types.

## Test User

After running the database seed script, you can use the following test user:

- Email: test@example.com
- Password: password123

## Development Resources

- A Postman collection for API testing is available in `/docs/koutu-api.postman_collection.json`
- To set up the development environment quickly, run the setup script: `./scripts/setup-dev.sh`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License

## Update 1
Polygon Annotation Feature
This document describes the polygon annotation feature added to the Koutu application, which allows users to create, view, and manage polygon annotations for garment images.
Features

Polygon Drawing: Interactive polygon creation on images
Polygon Storage: Secure storage of polygon data with image associations
Polygon Viewing: View all polygons for an image
Polygon Management: Edit and delete polygons

Technical Implementation
Backend Components

Database Schema:

New polygons table with foreign key references to original_images
Stores polygon vertices, metadata, and relationship to parent image
Implements trigger to track polygon count per image


API Endpoints:

POST /api/v1/polygons: Create a new polygon
GET /api/v1/polygons/image/:imageId: Get all polygons for an image
GET /api/v1/polygons/:id: Get a specific polygon
PUT /api/v1/polygons/:id: Update a polygon
DELETE /api/v1/polygons/:id: Delete a polygon


Data Storage:

Polygon data stored in PostgreSQL database
Additional JSON files stored in Firebase Storage for AI/ML operations
Each polygon maintains a parent-child relationship with its original image



Frontend Components

PolygonDrawer: React component for creating polygons on images

Uses React Konva for canvas manipulation
Provides drawing interface with point placement
Handles polygon completion and submission


PolygonViewer: Component for displaying existing polygons

Renders polygons with unique colors
Supports polygon selection
Shows polygon metadata


PolygonList: Component for managing polygon annotations

Lists all polygons for an image
Provides deletion functionality
Supports polygon selection


ImageAnnotationPage: Integrated page for annotation workflow

Combines drawing, viewing, and management components
Supports toggling between view and draw modes
Shows polygon metadata



Data Structure
Each polygon consists of:

Array of points (x, y coordinates)
Metadata including label, original image dimensions, and scaling information
Reference to parent image via original_image_id

Integration with AI/ML Pipeline
The polygon data is designed to be easily used for AI/ML training:

All polygons are stored with normalized coordinates
Original image dimensions are preserved in metadata
Additional JSON files are created in Firebase Storage
Each JSON file contains both polygon and parent image information

Usage Flow

User uploads an image to the platform
User navigates to the image annotation page
User toggles to "Draw Mode" and creates polygon(s) around garments
System stores the polygon data with image association
User can view and manage all polygons for an image

Future Enhancements

Automatic labeling of polygons using AI
Bulk polygon operations
Annotation templates for common garment types
Multi-user annotation with conflict resolution
Annotation quality metrics and validation