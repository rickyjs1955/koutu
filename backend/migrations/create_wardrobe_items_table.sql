-- /backend/migrations/create_wardrobe_items_table.sql

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

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
CREATE INDEX IF NOT EXISTS idx_wardrobe_items_position ON wardrobe_items(wardrobe_id, position);