-- /backend/src/db/test_schema.sql
-- FINAL CORRECTED SCHEMA that matches both garmentModel.ts AND test expectations

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- Drop existing tables if they exist (in reverse dependency order)
DROP TABLE IF EXISTS wardrobe_items CASCADE;
DROP TABLE IF EXISTS garment_items CASCADE;
DROP TABLE IF EXISTS original_images CASCADE;
DROP TABLE IF EXISTS wardrobes CASCADE;
DROP TABLE IF EXISTS user_oauth_providers CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS polygons CASCADE; -- Added for completeness if it exists elsewhere
DROP TABLE IF EXISTS test_items CASCADE;
DROP TABLE IF EXISTS test_table CASCADE;
DROP TABLE IF EXISTS parent_cleanup CASCADE;
DROP TABLE IF EXISTS child_cleanup CASCADE;
DROP TABLE IF EXISTS exclude_test_table CASCADE;


-- Create users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  display_name VARCHAR(255),
  profile_image_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user OAuth providers table
CREATE TABLE user_oauth_providers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,
  provider_id VARCHAR(255) NOT NULL,
  provider_email VARCHAR(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_id)
);

-- Create original images table
CREATE TABLE original_images (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL,
  original_filename VARCHAR(255),
  mime_type VARCHAR(100),
  file_size INTEGER,
  original_metadata JSONB DEFAULT '{}',
  upload_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status VARCHAR(20) DEFAULT 'new' CHECK (status IN ('new', 'processed', 'labeled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CRITICAL FIX: Create garment_items table that satisfies BOTH requirements:
-- 1. garmentModel.ts interface (id, user_id, original_image_id, file_path, mask_path, metadata, data_version, etc.)
-- 2. Test expectations (name column for test queries AND tags column for garment item properties)
CREATE TABLE garment_items (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
  
  -- Fields required by garmentModel.ts
  file_path TEXT NOT NULL,
  mask_path TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  data_version INTEGER DEFAULT 1,
  
  -- Additional fields expected by tests and comprehensive model
  name VARCHAR(255),
  description TEXT,
  category VARCHAR(100),
  color VARCHAR(100),
  brand VARCHAR(255),
  size VARCHAR(50),
  price DECIMAL(10,2),
  purchase_date DATE,
  image_url TEXT,
  
  -- NEW: Add tags column as TEXT array to match test expectations
  tags TEXT[], 
  
  -- Standard timestamp fields
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create wardrobes table
CREATE TABLE wardrobes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  is_default BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create wardrobe_items table
CREATE TABLE wardrobe_items (
  id SERIAL PRIMARY KEY,
  wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
  garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
  position INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(wardrobe_id, garment_item_id)
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_original_images_user_id ON original_images(user_id);
CREATE INDEX idx_original_images_status ON original_images(status);
CREATE INDEX idx_original_images_upload_date ON original_images(upload_date DESC);
CREATE INDEX idx_garment_items_user_id ON garment_items(user_id);
CREATE INDEX idx_garment_items_original_image_id ON garment_items(original_image_id);
CREATE INDEX idx_garment_items_created_at ON garment_items(created_at DESC);
CREATE INDEX idx_garment_items_data_version ON garment_items(data_version);
CREATE INDEX idx_garment_items_category ON garment_items(category);
CREATE INDEX idx_garment_items_name ON garment_items(name);
-- NEW: Add index for tags column
CREATE INDEX idx_garment_items_tags ON garment_items USING GIN (tags);
CREATE INDEX idx_wardrobes_user_id ON wardrobes(user_id);
CREATE INDEX idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
CREATE INDEX idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
CREATE INDEX idx_wardrobe_items_position ON wardrobe_items(wardrobe_id, position);
CREATE INDEX idx_wardrobe_items_created_at ON wardrobe_items(created_at DESC);

-- Add JSON indexes for better metadata query performance
CREATE INDEX idx_garment_items_metadata_gin ON garment_items USING GIN (metadata);
CREATE INDEX idx_original_images_metadata_gin ON original_images USING GIN (original_metadata);

-- Create test-specific tables for additional testing
CREATE TABLE IF NOT EXISTS test_items (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS test_table (
  id SERIAL PRIMARY KEY,
  value TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS parent_cleanup (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS child_cleanup (
  id SERIAL PRIMARY KEY,
  parent_id INTEGER,
  description TEXT,
  CONSTRAINT fk_parent FOREIGN KEY (parent_id) REFERENCES parent_cleanup(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS exclude_test_table (
  id SERIAL PRIMARY KEY,
  range INT4RANGE,
  EXCLUDE USING gist (range WITH &&)
);

-- Polygons table is created by migration 003_add_polygons.sql
-- No need to create it here

-- Grant permissions (if needed)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;