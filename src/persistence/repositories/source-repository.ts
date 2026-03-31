import { query } from '../database';
import logger from '../../logging';

export interface Source {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  lastSuccessAt: Date | null;
  lastFailureAt: Date | null;
  lastError: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export class SourceRepository {
  async findByName(name: string): Promise<Source | null> {
    const result = await query(
      'SELECT * FROM sources WHERE name = $1',
      [name]
    );
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRow(result.rows[0]);
  }

  async findAllEnabled(): Promise<Source[]> {
    const result = await query(
      'SELECT * FROM sources WHERE enabled = true ORDER BY name'
    );
    
    return result.rows.map(row => this.mapRow(row));
  }

  async updateSuccess(id: number): Promise<void> {
    await query(
      'UPDATE sources SET last_success_at = NOW(), updated_at = NOW() WHERE id = $1',
      [id]
    );
  }

  async updateFailure(id: number, errorMessage: string): Promise<void> {
    await query(
      'UPDATE sources SET last_failure_at = NOW(), last_error = $1, updated_at = NOW() WHERE id = $2',
      [errorMessage, id]
    );
  }

  private mapRow(row: any): Source {
    return {
      id: row.id,
      name: row.name,
      type: row.type,
      enabled: row.enabled,
      lastSuccessAt: row.last_success_at,
      lastFailureAt: row.last_failure_at,
      lastError: row.last_error,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
