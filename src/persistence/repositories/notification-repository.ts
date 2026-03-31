import { query } from '../database';
import logger from '../../logging';

export interface NotificationEvent {
  id: number;
  advisoryId: number;
  notificationType: string;
  channel: string;
  status: string;
  slackMessageRef: string | null;
  sentAt: Date | null;
  errorMessage: string | null;
}

export class NotificationRepository {
  async create(
    advisoryId: number,
    notificationType: string,
    channel: string,
    status: string,
    slackMessageRef: string | null = null,
    errorMessage: string | null = null
  ): Promise<number> {
    const result = await query(
      `INSERT INTO notification_events (
        advisory_id, notification_type, channel, status, 
        slack_message_ref, sent_at, error_message
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id`,
      [
        advisoryId,
        notificationType,
        channel,
        status,
        slackMessageRef,
        status === 'sent' ? new Date() : null,
        errorMessage,
      ]
    );

    return result.rows[0].id;
  }

  async hasBeenNotified(advisoryId: number, notificationType: string): Promise<boolean> {
    const result = await query(
      `SELECT id FROM notification_events 
       WHERE advisory_id = $1 AND notification_type = $2 AND status = 'sent'
       LIMIT 1`,
      [advisoryId, notificationType]
    );

    return result.rows.length > 0;
  }
}

export class DigestRunRepository {
  async create(startedAt: Date): Promise<number> {
    const result = await query(
      `INSERT INTO digest_runs (started_at, status) 
       VALUES ($1, 'running') 
       RETURNING id`,
      [startedAt]
    );

    return result.rows[0].id;
  }

  async updateSuccess(id: number, itemsIncluded: number, slackMessageRef: string | null): Promise<void> {
    await query(
      `UPDATE digest_runs 
       SET finished_at = NOW(), status = 'success', 
           items_included = $1, slack_message_ref = $2
       WHERE id = $3`,
      [itemsIncluded, slackMessageRef, id]
    );
  }

  async updateFailure(id: number, errorMessage: string): Promise<void> {
    await query(
      `UPDATE digest_runs 
       SET finished_at = NOW(), status = 'failed', error_message = $1
       WHERE id = $2`,
      [errorMessage, id]
    );
  }

  async findLatest(): Promise<Date | null> {
    const result = await query(
      `SELECT finished_at FROM digest_runs 
       WHERE status = 'success' 
       ORDER BY finished_at DESC 
       LIMIT 1`
    );

    if (result.rows.length === 0) {
      return null;
    }

    return result.rows[0].finished_at;
  }
}
