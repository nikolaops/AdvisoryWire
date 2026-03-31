import { query, getClient } from '../database';
import { NormalizedAdvisory, StoredAdvisory, DeduplicationResult } from '../../shared/types';
import logger from '../../logging';

export class AdvisoryRepository {
  async findBySourceAndExternalId(sourceId: number, externalId: string): Promise<StoredAdvisory | null> {
    const result = await query(
      'SELECT * FROM advisories WHERE source_id = $1 AND external_id = $2',
      [sourceId, externalId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRow(result.rows[0]);
  }

  async findByCveId(cveId: string): Promise<StoredAdvisory[]> {
    const result = await query(
      `SELECT a.* FROM advisories a
       INNER JOIN advisory_identifiers ai ON ai.advisory_id = a.id
       WHERE ai.identifier_type = 'CVE' AND ai.identifier_value = $1`,
      [cveId]
    );

      return result.rows.map((row: any) => this.mapRow(row));
  }

  async checkDuplication(sourceId: number, externalId: string, rawHash: string): Promise<DeduplicationResult> {
    const existing = await this.findBySourceAndExternalId(sourceId, externalId);

    if (!existing) {
      return { isNew: true };
    }

    const isDifferent = existing.rawHash !== rawHash;

    return {
      isNew: false,
      existingAdvisoryId: existing.id,
      isDifferent,
    };
  }

  async create(sourceId: number, advisory: NormalizedAdvisory): Promise<number> {
    const client = await getClient();

    try {
      await client.query('BEGIN');

      // Insert advisory
      const advisoryResult = await client.query(
        `INSERT INTO advisories (
          source_id, external_id, title, summary, severity, vendor,
          published_at, updated_at, exploit_status, status, raw_hash, raw_payload
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id`,
        [
          sourceId,
          advisory.externalId,
          advisory.title,
          advisory.summary,
          advisory.severity,
          advisory.vendor,
          advisory.publishedAt,
          advisory.updatedAt,
          advisory.exploitStatus,
          advisory.status,
          advisory.rawHash,
          JSON.stringify(advisory.rawPayload),
        ]
      );

      const advisoryId = advisoryResult.rows[0].id;

      // Insert identifiers (CVEs)
      for (const cveId of advisory.cveIds) {
        await client.query(
          `INSERT INTO advisory_identifiers (advisory_id, identifier_type, identifier_value)
           VALUES ($1, 'CVE', $2)
           ON CONFLICT DO NOTHING`,
          [advisoryId, cveId]
        );
      }

      // Insert source-native identifier
      await client.query(
        `INSERT INTO advisory_identifiers (advisory_id, identifier_type, identifier_value)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [advisoryId, advisory.source, advisory.externalId]
      );

      // Insert references
      for (const ref of advisory.references) {
        await client.query(
          `INSERT INTO advisory_references (advisory_id, url, label)
           VALUES ($1, $2, $3)`,
          [advisoryId, ref.url, ref.label]
        );
      }

      await client.query('COMMIT');

      logger.info({ advisoryId, externalId: advisory.externalId }, 'Advisory created');

      return advisoryId;
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error({ error, externalId: advisory.externalId }, 'Failed to create advisory');
      throw error;
    } finally {
      client.release();
    }
  }

  async update(advisoryId: number, advisory: NormalizedAdvisory): Promise<void> {
    await query(
      `UPDATE advisories SET
        title = $1, summary = $2, severity = $3, vendor = $4,
        updated_at = $5, exploit_status = $6, status = $7,
        raw_hash = $8, raw_payload = $9, modified_at = NOW()
       WHERE id = $10`,
      [
        advisory.title,
        advisory.summary,
        advisory.severity,
        advisory.vendor,
        advisory.updatedAt,
        advisory.exploitStatus,
        advisory.status,
        advisory.rawHash,
        JSON.stringify(advisory.rawPayload),
        advisoryId,
      ]
    );

    logger.info({ advisoryId, externalId: advisory.externalId }, 'Advisory updated');
  }

  async findById(id: number): Promise<StoredAdvisory | null> {
    const result = await query(
      'SELECT * FROM advisories WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRow(result.rows[0]);
  }

  async findNotNotified(notificationType: string, limit: number = 100): Promise<StoredAdvisory[]> {
    const result = await query(
      `SELECT a.* FROM advisories a
       WHERE NOT EXISTS (
         SELECT 1 FROM notification_events ne
         WHERE ne.advisory_id = a.id 
         AND ne.notification_type = $1
         AND ne.status = 'sent'
       )
       ORDER BY a.published_at DESC
       LIMIT $2`,
      [notificationType, limit]
    );

    return result.rows.map(row => this.mapRow(row));
  }

  private mapRow(row: any): StoredAdvisory {
    return {
      id: row.id,
      sourceId: row.source_id,
      externalId: row.external_id,
      source: 'stored',
      title: row.title,
      summary: row.summary,
      severity: row.severity,
      vendor: row.vendor,
      publishedAt: row.published_at,
      updatedAt: row.updated_at,
      cveIds: [],
      references: [],
      tags: [],
      exploitStatus: row.exploit_status,
      status: row.status,
      rawHash: row.raw_hash,
      rawPayload: row.raw_payload,
      createdAt: row.created_at,
      modifiedAt: row.modified_at,
    };
  }
}
