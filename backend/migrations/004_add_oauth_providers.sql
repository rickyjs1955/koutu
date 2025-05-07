-- migrations/004_add_oauth_providers.sql

-- Add OAuth related fields to users table
ALTER TABLE users ADD COLUMN oauth_provider VARCHAR(50) NULL;
ALTER TABLE users ADD COLUMN oauth_id VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN avatar_url VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN name VARCHAR(255) NULL;

-- Create indexes for OAuth fields
CREATE INDEX IF NOT EXISTS idx_users_oauth_provider ON users(oauth_provider) WHERE oauth_provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_oauth_id ON users(oauth_id) WHERE oauth_id IS NOT NULL;

-- Create a unique constraint for OAuth provider + ID
CREATE UNIQUE INDEX idx_users_oauth ON users (oauth_provider, oauth_id) 
  WHERE oauth_provider IS NOT NULL AND oauth_id IS NOT NULL;

-- Allow NULL password_hash for OAuth users
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Create table for linked accounts (for users who want to link multiple providers)
CREATE TABLE IF NOT EXISTS user_oauth_providers (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,
  provider_id VARCHAR(255) NOT NULL,
  access_token TEXT NULL,
  refresh_token TEXT NULL,
  token_expires_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  UNIQUE(provider, provider_id)
);

-- Add proper indexes for the oauth providers table
CREATE INDEX IF NOT EXISTS idx_user_oauth_providers_user_id ON user_oauth_providers(user_id);
CREATE INDEX IF NOT EXISTS idx_user_oauth_providers_provider ON user_oauth_providers(provider);
CREATE INDEX IF NOT EXISTS idx_user_oauth_providers_combo ON user_oauth_providers(provider, provider_id);

-- Add a function to handle duplicate email scenarios for OAuth users
CREATE OR REPLACE FUNCTION merge_oauth_accounts()
RETURNS TRIGGER AS $$
BEGIN
  -- If we're inserting/updating a user with OAuth and there's a duplicate email
  -- We'll handle this in the application code for more control
  -- This function is a placeholder for future functionality
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create a trigger for email conflict resolution (placeholder)
-- Actual conflict resolution handled in application code
CREATE TRIGGER oauth_email_conflict_trigger
BEFORE INSERT OR UPDATE ON users
FOR EACH ROW
WHEN (NEW.oauth_provider IS NOT NULL)
EXECUTE FUNCTION merge_oauth_accounts();