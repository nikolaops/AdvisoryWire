import { query } from '../database';

export interface SourceFetchRun {
  id: number;
  sourceId: number;
  startedAt: Date;
  finishedAt: Date | null;
  status: string;
  itemsFetched: number;
  errorMessage: string | null;
}

export class SourceFetchRunRepository {
  async create(sourceId: number, startedAt: Date): Promise<number> {
    const result = await query(
      `INSERT INTO source_fetch_runs (source_id, started_at, status) 
       VALUES ($1, $2, 'running') 
       RETURNING id`,
      [sourceId, startedAt]
    );
    
    return result.rows[0].id;
  }

  async updateSuccess(id: number, itemsFetched: number): Promise<void> {
    await query(
      `UPDATE source_fetch_runs 
       SET finished_at = NOW(), status = 'success', items_fetched = $1 
       WHERE id = $2`,
      [itemsFetched, id]
    );
  }

  async updateFailure(id: number, errorMessage: string): Promise<void> {
    await query(
      `UPDATE source_fetch_runs 
       SET finished_at = NOW(), status = 'failed', error_message = $1 
       WHERE id = $2`,
      [errorMessage, id]
    );
  }

  async findLatestBySource(sourceId: number): Promise<SourceFetchRun | null> {
    const result = await query(
      `SELECT * FROM source_fetch_runs 
       WHERE source_id = $1 
       ORDER BY started_at DESC 
       LIMIT 1`,
      [sourceId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRow(result.rows[0]);
  }

  private mapRow(row: any): SourceFetchRun {
    return {
      id: row.id,
      sourceId: row.source_id,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
      status: row.status,
      itemsFetched: row.items_fetched,
      errorMessage: row.error_message,
    };
  }
}
