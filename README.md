# Fashion Data Collector Backend

This is a Node.js + TypeScript backend application for collecting garment data through user-submitted images and manual background removal. The application serves as a data collection platform for a future AI-powered fashion application.

## Features

- **User Authentication**: Register and login to securely access your data
- **Image Upload**: Upload images of clothing items
- **Garment Extraction**: Tools to create garment cutouts with masks
- **Digital Wardrobe**: Organize extracted garments into collections
- **Data Export**: Export functionality for future migration to AI platform

## Prerequisites

- Node.js (v16+)
- PostgreSQL (v13+)
- TypeScript

## Installation

1. Clone the repository
   ```
   git clone https://github.com/yourusername/fashion-data-collector-backend.git
   cd fashion-data-collector-backend
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Configure environment variables
   - Copy `.env.example` to `.env`
   - Update the database connection string and other settings

4. Set up the database
   ```
   npm run setup-db
   ```
   This will:
   - Run migrations to create the necessary tables
   - Seed the database with test data

## Running the Application

### Development mode
```
npm run dev
```

### Production mode
```
npm run build
npm start
```

## API Documentation

### Authentication

- **POST** `/api/v1/auth/register`: Register a new user
  - Request body: `{ "email": "user@example.com", "password": "password123" }`

- **POST** `/api/v1/auth/login`: Login and get JWT token
  - Request body: `{ "email": "user@example.com", "password": "password123" }`

- **GET** `/api/v1/auth/me`: Get current user details (requires authentication)

### Images

- **POST** `/api/v1/images/upload`: Upload a new image (requires authentication)
  - Form data: `image` (file)

- **GET** `/api/v1/images`: Get all user images (requires authentication)

- **GET** `/api/v1/images/:id`: Get a specific image (requires authentication)

- **DELETE** `/api/v1/images/:id`: Delete an image (requires authentication)

### Garments

- **POST** `/api/v1/garments/create`: Create a new garment from mask data (requires authentication)
  - Request body: 
    ```json
    {
      "originalImageId": "uuid",
      "maskData": {
        "width": 800,
        "height": 600,
        "data": [0, 0, 255, 255, ...]
      },
      "metadata": {
        "type": "shirt",
        "color": "blue",
        "pattern": "solid",
        "season": "summer"
      }
    }
    ```

- **GET** `/api/v1/garments`: Get all user garments (requires authentication)

- **GET** `/api/v1/garments/:id`: Get a specific garment (requires authentication)

- **PUT** `/api/v1/garments/:id/metadata`: Update garment metadata (requires authentication)
  - Request body: 
    ```json
    {
      "metadata": {
        "type": "shirt",
        "color": "red",
        "pattern": "striped",
        "season": "spring"
      }
    }
    ```

- **DELETE** `/api/v1/garments/:id`: Delete a garment (requires authentication)

### Wardrobes

- **POST** `/api/v1/wardrobes`: Create a new wardrobe (requires authentication)
  - Request body: `{ "name": "Summer Collection", "description": "My summer outfits" }`

- **GET** `/api/v1/wardrobes`: Get all user wardrobes (requires authentication)

- **GET** `/api/v1/wardrobes/:id`: Get a specific wardrobe with its garments (requires authentication)

- **PUT** `/api/v1/wardrobes/:id`: Update wardrobe details (requires authentication)
  - Request body: `{ "name": "Updated Name", "description": "Updated description" }`

- **POST** `/api/v1/wardrobes/:id/items`: Add a garment to wardrobe (requires authentication)
  - Request body: `{ "garmentId": "uuid", "position": 0 }`

- **DELETE** `/api/v1/wardrobes/:id/items/:itemId`: Remove a garment from wardrobe (requires authentication)

- **DELETE** `/api/v1/wardrobes/:id`: Delete a wardrobe (requires authentication)

### Data Export

- **GET** `/api/v1/export/data`: Export user data as JSON (requires authentication)

- **GET** `/api/v1/export/file`: Export user data to a file (requires authentication)

## Project Structure

```
backend/
├── src/
│   ├── config/                 # Configuration files
│   ├── controllers/            # Request handlers
│   ├── middlewares/            # Custom middleware functions
│   ├── models/                 # Database models
│   ├── routes/                 # API route definitions
│   ├── services/               # Business logic
│   ├── utils/                  # Helper functions
│   ├── validators/             # Input validation
│   └── app.ts                  # Main application setup
├── migrations/                 # Database migrations
├── scripts/                    # Utility scripts
├── tests/                      # Tests
├── uploads/                    # Image storage
├── exports/                    # Data export files
├── package.json
├── tsconfig.json
└── README.md
```

## Test User

After running the database seed script, you can use the following test user:

- Email: test@example.com
- Password: password123

## Data Migration

The export functionality formats data in a way that will be compatible with the future AI fashion application. The exported data includes:

- User information
- Original images
- Extracted garments with metadata
- Wardrobe collections

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License