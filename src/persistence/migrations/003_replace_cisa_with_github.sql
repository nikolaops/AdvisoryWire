-- Replace cisa-kev source with github-advisory
INSERT INTO sources (name, type, enabled)
VALUES ('github-advisory', 'github_advisory', true)
ON CONFLICT (name) DO UPDATE SET enabled = true;

-- Disable cisa-kev (keep data, just disable polling)
UPDATE sources SET enabled = false WHERE name = 'cisa-kev';

-- Reset OSV last_success_at so it re-fetches with correct severity parsing
UPDATE sources SET last_success_at = NULL WHERE name = 'osv';
