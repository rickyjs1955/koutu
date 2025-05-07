-- migrations/002_fix_indexes.sql

-- PostgreSQL uses CREATE INDEX, not the INDEX keyword in table definitions
-- This migration fixes that issue

-- Drop invalid indexes from initial migration
ALTER TABLE original_images DROP CONSTRAINT IF EXISTS idx_original_images_user_id;
ALTER TABLE garment_items DROP CONSTRAINT IF EXISTS idx_garment_items_user_id;
ALTER TABLE garment_items DROP CONSTRAINT IF EXISTS idx_garment_items_original_image_id;
ALTER TABLE wardrobes DROP CONSTRAINT IF EXISTS idx_wardrobes_user_id;
ALTER TABLE wardrobe_items DROP CONSTRAINT IF EXISTS idx_wardrobe_items_garment_item_id;

-- Create proper indexes
CREATE INDEX IF NOT EXISTS idx_original_images_user_id ON original_images(user_id);
CREATE INDEX IF NOT EXISTS idx_garment_items_user_id ON garment_items(user_id);
CREATE INDEX IF NOT EXISTS idx_garment_items_original_image_id ON garment_items(original_image_id);
CREATE INDEX IF NOT EXISTS idx_wardrobes_user_id ON wardrobes(user_id);
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_garment_item_id ON wardrobe_items(garment_item_id);

-- Add metadata indexes for common queries
CREATE INDEX IF NOT EXISTS idx_garment_items_metadata_gin ON garment_items USING GIN (metadata);

-- Add index on user email for faster lookups during authentication
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);