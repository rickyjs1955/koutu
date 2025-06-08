-- docker/postgres/init-test.sql
-- Updated initialization script for test database

-- Create the test database
CREATE DATABASE koutu_test;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE koutu_test TO postgres;

-- Connect to the new database and create schema
\c koutu_test

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    display_name VARCHAR(255),
    profile_image_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user OAuth providers table
CREATE TABLE IF NOT EXISTS user_oauth_providers (
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
CREATE TABLE IF NOT EXISTS original_images (
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

-- Create garment items table
CREATE TABLE IF NOT EXISTS garment_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_image_id UUID REFERENCES original_images(id) ON DELETE SET NULL,
    name VARCHAR(255),
    description TEXT,
    category VARCHAR(100),
    color VARCHAR(100),
    brand VARCHAR(255),
    size VARCHAR(50),
    price DECIMAL(10,2),
    purchase_date DATE,
    image_url TEXT,
    file_path TEXT,
    mask_path TEXT,
    metadata JSONB DEFAULT '{}',
    data_version INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create wardrobes table
CREATE TABLE IF NOT EXISTS wardrobes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CREATE POLYGONS TABLE (This was missing!)
CREATE TABLE IF NOT EXISTS polygons (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
    points JSONB NOT NULL,
    label VARCHAR(255) NOT NULL,
    metadata JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'active',
    version INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Enhanced constraints
    CONSTRAINT points_is_array CHECK (jsonb_typeof(points) = 'array'),
    CONSTRAINT points_min_length CHECK (jsonb_array_length(points) >= 3),
    CONSTRAINT points_max_length CHECK (jsonb_array_length(points) <= 1000),
    CONSTRAINT label_not_empty CHECK (LENGTH(TRIM(label)) > 0),
    CONSTRAINT status_valid CHECK (status IN ('active', 'deleted', 'archived'))
);

-- Create test-specific tables
CREATE TABLE IF NOT EXISTS test_table (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_original_images_user_id ON original_images(user_id);
CREATE INDEX IF NOT EXISTS idx_original_images_status ON original_images(status);
CREATE INDEX IF NOT EXISTS idx_original_images_upload_date ON original_images(upload_date DESC);

CREATE INDEX IF NOT EXISTS idx_garment_items_user_id ON garment_items(user_id);
CREATE INDEX IF NOT EXISTS idx_garment_items_original_image_id ON garment_items(original_image_id);

CREATE INDEX IF NOT EXISTS idx_wardrobes_user_id ON wardrobes(user_id);

CREATE INDEX IF NOT EXISTS idx_polygons_user_id ON polygons(user_id);
CREATE INDEX IF NOT EXISTS idx_polygons_image_id ON polygons(original_image_id);
CREATE INDEX IF NOT EXISTS idx_polygons_status ON polygons(status);
CREATE INDEX IF NOT EXISTS idx_polygons_created_at ON polygons(created_at);
CREATE INDEX IF NOT EXISTS idx_polygons_label_gin ON polygons USING gin(to_tsvector('english', label));
CREATE INDEX IF NOT EXISTS idx_polygons_metadata_gin ON polygons USING gin(metadata);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER IF NOT EXISTS update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER IF NOT EXISTS update_original_images_updated_at 
    BEFORE UPDATE ON original_images 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER IF NOT EXISTS update_garment_items_updated_at 
    BEFORE UPDATE ON garment_items 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER IF NOT EXISTS update_wardrobes_updated_at 
    BEFORE UPDATE ON wardrobes 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER IF NOT EXISTS update_polygons_updated_at 
    BEFORE UPDATE ON polygons 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Grant table permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;