-- migrations/003_add_polygons.sql

-- Create polygons table
CREATE TABLE IF NOT EXISTS polygons (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
  points JSONB NOT NULL,
  label VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_polygons_user_id ON polygons(user_id);
CREATE INDEX IF NOT EXISTS idx_polygons_original_image_id ON polygons(original_image_id);
CREATE INDEX IF NOT EXISTS idx_polygons_label ON polygons(label);

-- Add GIN index for JSON queries on points and metadata
CREATE INDEX IF NOT EXISTS idx_polygons_points_gin ON polygons USING GIN (points jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_polygons_metadata_gin ON polygons USING GIN (metadata jsonb_path_ops);

-- Update original_images table to add a polygons_count column for quick counting
ALTER TABLE original_images ADD COLUMN IF NOT EXISTS polygons_count INTEGER NOT NULL DEFAULT 0;

-- Create a function to update the polygons_count
CREATE OR REPLACE FUNCTION update_image_polygons_count()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    UPDATE original_images 
    SET polygons_count = polygons_count + 1 
    WHERE id = NEW.original_image_id;
  ELSIF TG_OP = 'DELETE' THEN
    UPDATE original_images 
    SET polygons_count = polygons_count - 1 
    WHERE id = OLD.original_image_id;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create a trigger to automatically update the count
CREATE TRIGGER update_image_polygons_count_trigger
AFTER INSERT OR DELETE ON polygons
FOR EACH ROW
EXECUTE FUNCTION update_image_polygons_count();