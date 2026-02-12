-- Add location_data column to devices table
ALTER TABLE devices ADD COLUMN IF NOT EXISTS location_data JSONB;
