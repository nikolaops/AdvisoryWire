import { readFileSync } from 'fs';
import { join } from 'path';
import { query } from '../database';
import logger from '../../logging';

const MIGRATIONS_DIR = __dirname;

interface Migration {
  name: string;
  path: string;
}

const migrations: Migration[] = [
  { name: '001_initial_schema', path: join(MIGRATIONS_DIR, '001_initial_schema.sql') },
  { name: '002_seed_sources', path: join(MIGRATIONS_DIR, '002_seed_sources.sql') },
  { name: '003_replace_cisa_with_github', path: join(MIGRATIONS_DIR, '003_replace_cisa_with_github.sql') },
  { name: '004_add_nvd_source', path: join(MIGRATIONS_DIR, '004_add_nvd_source.sql') },
];

export async function runMigrations(): Promise<void> {
  logger.info('Starting database migrations');

  // Create migrations tracking table
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    )
  `);

  for (const migration of migrations) {
    try {
      // Check if already applied
      const result = await query(
        'SELECT name FROM schema_migrations WHERE name = $1',
        [migration.name]
      );

      if (result.rows.length > 0) {
        logger.info({ migration: migration.name }, 'Migration already applied, skipping');
        continue;
      }

      logger.info({ migration: migration.name }, 'Applying migration');

      // Read and execute migration SQL
      const sql = readFileSync(migration.path, 'utf-8');
      await query(sql);

      // Record migration
      await query(
        'INSERT INTO schema_migrations (name) VALUES ($1)',
        [migration.name]
      );

      logger.info({ migration: migration.name }, 'Migration applied successfully');
    } catch (error) {
      logger.error({ error, migration: migration.name }, 'Migration failed');
      throw error;
    }
  }

  logger.info('All migrations completed successfully');
}

// Run migrations if executed directly
if (require.main === module) {
  runMigrations()
    .then(() => {
      logger.info('Migrations completed');
      process.exit(0);
    })
    .catch((error) => {
      logger.error({ error }, 'Migration process failed');
      process.exit(1);
    });
}
