// scripts/seedDatabase.ts
import { Pool } from 'pg';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';

// Load environment variables
dotenv.config();

const run = async () => {
  // Create a database connection
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    // Start a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      console.log('Creating test user...');
      
      // Hash password
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash('password123', saltRounds);
      
      // Create test user
      const userId = uuidv4();
      await client.query(
        'INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())',
        [userId, 'test@example.com', passwordHash]
      );
      
      console.log('Test user created with ID:', userId);
      
      // Create sample wardrobes
      console.log('Creating sample wardrobes...');
      
      const wardrobe1Id = uuidv4();
      const wardrobe2Id = uuidv4();
      
      await client.query(
        'INSERT INTO wardrobes (id, user_id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())',
        [wardrobe1Id, userId, 'Summer Collection', 'My summer outfits']
      );
      
      await client.query(
        'INSERT INTO wardrobes (id, user_id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())',
        [wardrobe2Id, userId, 'Winter Collection', 'Warm clothes for winter']
      );
      
      console.log('Sample wardrobes created with IDs:', wardrobe1Id, wardrobe2Id);
      
      // Create sample images (if uploads folder exists)
      const uploadsDir = path.join(__dirname, '../uploads');
      if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
      }
      
      // Create placeholder images
      console.log('Creating placeholder images...');
      
      // Simple 100x100 image with color (blue)
      const image1Path = path.join(uploadsDir, 'sample1.png');
      const image2Path = path.join(uploadsDir, 'sample2.png');
      
      // Generate simple color squares as placeholder images
      // In a real scenario, you would have actual images
      // Here we'll just create entries in the database
      
      const image1Id = uuidv4();
      const image2Id = uuidv4();
      
      await client.query(
        `INSERT INTO original_images 
         (id, user_id, file_path, original_metadata, upload_date, status) 
         VALUES ($1, $2, $3, $4, NOW(), 'new')`,
        [image1Id, userId, 'uploads/sample1.png', JSON.stringify({
          width: 100,
          height: 100,
          format: 'png',
          filename: 'blue_shirt.png'
        })]
      );
      
      await client.query(
        `INSERT INTO original_images 
         (id, user_id, file_path, original_metadata, upload_date, status) 
         VALUES ($1, $2, $3, $4, NOW(), 'labeled')`,
        [image2Id, userId, 'uploads/sample2.png', JSON.stringify({
          width: 100,
          height: 100,
          format: 'png',
          filename: 'black_pants.png'
        })]
      );
      
      console.log('Sample images created with IDs:', image1Id, image2Id);
      
      // Create sample garments
      console.log('Creating sample garments...');
      
      const garment1Id = uuidv4();
      const garment2Id = uuidv4();
      
      await client.query(
        `INSERT INTO garment_items 
         (id, user_id, original_image_id, file_path, mask_path, metadata, created_at, updated_at, data_version) 
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), 1)`,
        [
          garment1Id, 
          userId, 
          image2Id, 
          'uploads/sample2_masked.png', 
          'uploads/sample2_mask.png',
          JSON.stringify({
            type: 'pants',
            color: 'black',
            season: 'all',
            brand: 'Example Brand',
            tags: ['casual', 'formal']
          })
        ]
      );
      
      // Add garment to wardrobe
      await client.query(
        'INSERT INTO wardrobe_items (wardrobe_id, garment_item_id, position) VALUES ($1, $2, $3)',
        [wardrobe1Id, garment1Id, 0]
      );
      
      console.log('Sample garment created with ID:', garment1Id);
      
      // Commit transaction
      await client.query('COMMIT');
      console.log('Database seeded successfully!');
      
      console.log('\nTest User Credentials:');
      console.log('Email: test@example.com');
      console.log('Password: password123');
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error seeding database:', err);
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Database connection error:', err);
  } finally {
    await pool.end();
  }
};

// Run the seed script
run();
