-- Add NVD source
INSERT INTO sources (name, type, enabled)
VALUES ('nvd', 'nvd', true)
ON CONFLICT (name) DO UPDATE SET enabled = true;
