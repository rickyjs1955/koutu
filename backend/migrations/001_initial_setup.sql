-- migrations/001_initial_setup.sql

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

-- Create indexes separately (after table creation)
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Original images table
CREATE TABLE IF NOT EXISTS original_images (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_path VARCHAR(255) NOT NULL,
  original_metadata JSONB NOT NULL DEFAULT '{}',
  upload_date TIMESTAMP NOT NULL,
  status VARCHAR(20) NOT NULL CHECK (status IN ('new', 'processed', 'labeled'))
);
CREATE INDEX idx_original_images_user_id ON original_images(user_id);

-- Garment items table
CREATE TABLE IF NOT EXISTS garment_items (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
  file_path VARCHAR(255) NOT NULL,
  mask_path VARCHAR(255) NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  data_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_garment_items_user_id ON garment_items(user_id);
CREATE INDEX idx_garment_items_original_image_id ON garment_items(original_image_id);

-- Wardrobes table
CREATE TABLE IF NOT EXISTS wardrobes (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_wardrobes_user_id ON wardrobes(user_id);

-- Wardrobe items junction table
CREATE TABLE IF NOT EXISTS wardrobe_items (
  wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
  garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
  position INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (wardrobe_id, garment_item_id)
);
CREATE INDEX idx_wardrobe_items_garment_item_id ON wardrobe_items(garment_item_id);