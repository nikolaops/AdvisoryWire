-- Insert default sources
INSERT INTO sources (name, type, enabled) VALUES 
    ('cisa-kev', 'cisa_kev', true),
    ('osv', 'osv', true)
ON CONFLICT (name) DO NOTHING;
