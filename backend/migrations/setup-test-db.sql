-- Database Setup Script for Wardrobe Integration Tests
-- /backend/setup-test-db.sql

-- Ensure wardrobes table has correct schema
ALTER TABLE wardrobes 
ADD COLUMN IF NOT EXISTS is_default BOOLEAN DEFAULT FALSE;

-- Update column types to handle longer content
ALTER TABLE wardrobes 
ALTER COLUMN name TYPE TEXT;

ALTER TABLE wardrobes 
ALTER COLUMN description TYPE TEXT;

-- Create wardrobe_items table if it doesn't exist
CREATE TABLE IF NOT EXISTS wardrobe_items (
    id SERIAL PRIMARY KEY,
    wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
    garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
    position INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(wardrobe_id, garment_item_id)
);

-- Create performance indexes
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_position ON wardrobe_items(wardrobe_id, position);

-- Ensure wardrobes table has proper indexes
CREATE INDEX IF NOT EXISTS idx_wardrobes_user_id ON wardrobes(user_id);
CREATE INDEX IF NOT EXISTS idx_wardrobes_name ON wardrobes(name);

-- Verify table structures
SELECT 
    table_name, 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name IN ('wardrobes', 'wardrobe_items')
ORDER BY table_name, ordinal_position;